"""
Core JWT analysis logic.

Decodes a JWT without verifying the signature, then runs a series of
security checks. Never sends the token anywhere — everything is local.
"""
import base64
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Finding:
    id: str
    severity: str          # critical | high | medium | low | info
    title: str
    description: str
    remediation: str
    evidence: str = ""


@dataclass
class AnalysisResult:
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    signature: str = ""
    raw: str = ""
    findings: list = field(default_factory=list)
    score: int = 100

    @property
    def algorithm(self) -> str:
        return self.header.get("alg", "unknown")

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)


# Sensitive keys commonly leaked in JWT payloads
SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "access_token", "refresh_token", "private_key",
    "credit_card", "ssn", "social_security", "bank_account",
}

# Algorithms that are considered weak for production
WEAK_ALGS = {"HS256", "HS384", "HS512"}
STRONG_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}


def b64url_decode(data: str) -> bytes:
    """Decode a base64url-encoded string with proper padding."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def decode_jwt(token: str) -> AnalysisResult:
    """Decode a JWT into its three parts without verifying the signature."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Invalid JWT: expected 3 parts separated by '.', got {len(parts)}"
        )

    result = AnalysisResult(raw=token)
    try:
        result.header = json.loads(b64url_decode(parts[0]))
    except Exception as exc:
        raise ValueError(f"Could not decode JWT header: {exc}") from exc

    try:
        result.payload = json.loads(b64url_decode(parts[1]))
    except Exception as exc:
        raise ValueError(f"Could not decode JWT payload: {exc}") from exc

    result.signature = parts[2]
    return result


def _ts(value: Any) -> str:
    """Convert a Unix timestamp to a human-readable UTC string."""
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except Exception:
        return str(value)


def analyze(token: str) -> AnalysisResult:
    """Run the full set of static checks against a JWT."""
    result = decode_jwt(token)
    header = result.header
    payload = result.payload
    alg = header.get("alg", "")

    # ── 1. alg=none ──────────────────────────────────────────────
    if alg.lower() == "none" or alg == "":
        result.add(Finding(
            id="ALG_NONE",
            severity="critical",
            title="Algorithm set to 'none' (no signature)",
            description=(
                "The token declares no signing algorithm. A server that "
                "honours this accepts arbitrary forged tokens — full "
                "authentication bypass."
            ),
            remediation=(
                "Reject alg=none on the server. Always pass an explicit "
                "allowlist of algorithms to your JWT library's verify call."
            ),
            evidence=f"alg = {alg!r}",
        ))

    # ── 2. Expiration ────────────────────────────────────────────
    now = int(time.time())
    if "exp" not in payload:
        result.add(Finding(
            id="NO_EXP",
            severity="high",
            title="Missing 'exp' claim",
            description=(
                "The token never expires. A leaked token is valid forever "
                "and cannot be aged out."
            ),
            remediation="Always set a short 'exp' (e.g. 15–60 minutes).",
        ))
    else:
        exp = payload["exp"]
        if int(exp) < now:
            result.add(Finding(
                id="EXPIRED",
                severity="high",
                title="Token is expired",
                description=(
                    "The 'exp' claim is in the past. A correct verifier "
                    "must reject this token."
                ),
                remediation="Issue a new token. Check server clock skew.",
                evidence=f"exp = {_ts(exp)} (now = {_ts(now)})",
            ))
        else:
            lifetime = int(exp) - int(payload.get("iat", now))
            if lifetime > 86400 * 7:
                result.add(Finding(
                    id="LONG_LIVED",
                    severity="medium",
                    title=f"Long-lived token ({lifetime // 3600}h)",
                    description=(
                        "The token is valid for more than 7 days. Long "
                        "lifetimes increase the blast radius of a leak."
                    ),
                    remediation="Shorten the lifetime and use refresh tokens.",
                    evidence=f"lifetime = {lifetime} seconds",
                ))

    # ── 3. Missing iat / nbf ─────────────────────────────────────
    if "iat" not in payload and "nbf" not in payload:
        result.add(Finding(
            id="NO_IAT",
            severity="low",
            title="Missing 'iat' and 'nbf' claims",
            description=(
                "Without issued-at or not-before, token lifetime is "
                "harder to reason about."
            ),
            remediation="Include 'iat' (and 'nbf' where relevant).",
        ))

    # ── 4. Sensitive data in payload ─────────────────────────────
    leaked = []
    for key in payload:
        if key.lower() in SENSITIVE_KEYS:
            leaked.append(key)
    if leaked:
        result.add(Finding(
            id="SENSITIVE_DATA",
            severity="medium",
            title="Sensitive data in payload",
            description=(
                "The payload contains keys that look sensitive. JWT "
                "payloads are base64-encoded, NOT encrypted — anyone "
                "with the token can read them."
            ),
            remediation=(
                "Remove sensitive values from the payload. Store them "
                "server-side and reference them by ID."
            ),
            evidence="Keys: " + ", ".join(leaked),
        ))

    # ── 5. Weak algorithm (informational) ────────────────────────
    if alg in WEAK_ALGS:
        result.add(Finding(
            id="WEAK_ALG",
            severity="medium",
            title=f"Symmetric algorithm in use ({alg})",
            description=(
                "HS256/384/512 use a shared secret. In multi-service "
                "architectures, every verifier must hold the same secret, "
                "which widens the trust boundary. Asymmetric algorithms "
                "(RS256, ES256) let verifiers hold only the public key."
            ),
            remediation=(
                "If multiple services verify tokens, migrate to RS256 or "
                "ES256. Keep HS256 only if a single service signs and verifies."
            ),
            evidence=f"alg = {alg}",
        ))

    # ── 6. kid / jku / x5u header injection ──────────────────────
    for risky in ("kid", "jku", "x5u", "x5c"):
        if risky in header:
            value = header[risky]
            if isinstance(value, str) and (
                ".." in value or value.startswith("http") or "/" in value
            ):
                result.add(Finding(
                    id=f"HEADER_{risky.upper()}",
                    severity="high",
                    title=f"Risky '{risky}' header value",
                    description=(
                        f"The '{risky}' header looks user-influenced. "
                        "Classic attacks inject a URL (jku/x5u) or a "
                        "path-traversal payload (kid) to force key confusion."
                    ),
                    remediation=(
                        f"Never trust '{risky}' from the token. Resolve "
                        "keys from a server-side allowlist only."
                    ),
                    evidence=f"{risky} = {value!r}",
                ))

    result.score = _score(result.findings)
    return result


def _score(findings: list) -> int:
    """Compute a 0–100 security score from findings (higher = better)."""
    weights = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
    penalty = sum(weights.get(f.severity, 0) for f in findings)
    return max(0, 100 - penalty)
