"""Tests for the SecurAI JWT Analyzer."""
import base64
import json
import sys
from pathlib import Path

# Allow running from repo root without install
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jwt_analyzer.analyzer import analyze, decode_jwt, b64url_decode
from jwt_analyzer.attacks import forge_none, brute_force_secret


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_token(header: dict, payload: dict, sig: str = "sig") -> str:
    h = _b64(json.dumps(header, separators=(",", ":")).encode())
    p = _b64(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{sig}"


# ── decode ───────────────────────────────────────────────────────
def test_decode_basic():
    token = _make_token({"alg": "HS256", "typ": "JWT"},
                        {"sub": "1234", "name": "Alice"})
    result = decode_jwt(token)
    assert result.header["alg"] == "HS256"
    assert result.payload["sub"] == "1234"


def test_decode_invalid_parts():
    try:
        decode_jwt("not.a.jwt.with.five.parts")
    except ValueError:
        return
    raise AssertionError("Expected ValueError")


# ── alg=none ─────────────────────────────────────────────────────
def test_alg_none_detected():
    token = _make_token({"alg": "none"}, {"sub": "1"}, sig="")
    result = analyze(token)
    ids = [f.id for f in result.findings]
    assert "ALG_NONE" in ids


# ── expiration ───────────────────────────────────────────────────
def test_missing_exp():
    token = _make_token({"alg": "HS256"}, {"sub": "1"})
    result = analyze(token)
    assert any(f.id == "NO_EXP" for f in result.findings)


def test_expired_token():
    token = _make_token({"alg": "HS256"}, {"sub": "1", "exp": 1000000})
    result = analyze(token)
    assert any(f.id == "EXPIRED" for f in result.findings)


# ── sensitive data ───────────────────────────────────────────────
def test_sensitive_payload_keys():
    token = _make_token({"alg": "RS256"}, {"password": "hunter2", "exp": 9999999999})
    result = analyze(token)
    assert any(f.id == "SENSITIVE_DATA" for f in result.findings)


# ── scoring ──────────────────────────────────────────────────────
def test_clean_token_scores_high():
    token = _make_token(
        {"alg": "RS256"},
        {"sub": "1", "exp": 9999999999, "iat": 1700000000},
    )
    result = analyze(token)
    assert result.score >= 80


def test_alg_none_scores_low():
    token = _make_token({"alg": "none"}, {"sub": "1"}, sig="")
    result = analyze(token)
    assert result.score < 80


# ── attacks ──────────────────────────────────────────────────────
def test_forge_none():
    token = _make_token({"alg": "HS256"}, {"sub": "1", "role": "user"}, sig="abc")
    forged = forge_none(token)
    parts = forged.split(".")
    assert len(parts) == 3
    header = json.loads(b64url_decode(parts[0]))
    assert header["alg"] == "none"
    assert parts[2] == ""


def test_brute_force_finds_secret(tmp_path):
    import hmac
    import hashlib

    secret = "password123"
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1", "exp": 9999999999}
    signing_input = (
        f"{_b64(json.dumps(header, separators=(',', ':')).encode())}."
        f"{_b64(json.dumps(payload, separators=(',', ':')).encode())}"
    ).encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    token = f"{signing_input.decode()}.{_b64(sig)}"

    wl = tmp_path / "words.txt"
    wl.write_text("foo\nbar\npassword123\nbaz\n")

    found = brute_force_secret(token, wl)
    assert found == "password123"


def test_brute_force_returns_none(tmp_path):
    import hmac
    import hashlib

    secret = "notinlist"
    header = {"alg": "HS256"}
    payload = {"sub": "1"}
    signing_input = (
        f"{_b64(json.dumps(header, separators=(',', ':')).encode())}."
        f"{_b64(json.dumps(payload, separators=(',', ':')).encode())}"
    ).encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    token = f"{signing_input.decode()}.{_b64(sig)}"

    wl = tmp_path / "words.txt"
    wl.write_text("foo\nbar\nbaz\n")

    assert brute_force_secret(token, wl) is None


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
