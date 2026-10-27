"""
tokens.py
A small, readable JWT implementation for the lab.

A JWT is three base64url parts joined by dots:  header.payload.signature
The header says which algorithm signs the token, the payload holds the claims
(who you are, your role, when it expires), and the signature is what proves the
server made it. Every attack in this lab is about breaking the link between the
payload and that signature.

A real app would use a library like PyJWT. This is written out by hand so that
the attacks are completely transparent. The server secret is weak on purpose so
the brute force attack can succeed.
"""

import hmac
import hashlib
import base64
import json
import time

# WEAK on purpose, so the brute force demo can crack it.
HS_SECRET = b"druk2024"


class JWTError(Exception):
    pass


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _hs256(signing_input: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, signing_input, hashlib.sha256).digest()


def issue(sub, role, ttl=3600, secret=HS_SECRET):
    """Create a normal, properly signed HS256 token."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": sub, "role": role, "exp": int(time.time()) + ttl}
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64u(_hs256(f"{h}.{p}".encode(), secret))
    return f"{h}.{p}.{sig}"


def decode_parts(token):
    parts = token.split(".")
    if len(parts) < 2:
        raise JWTError("not a token")
    header = json.loads(b64u_dec(parts[0]))
    payload = json.loads(b64u_dec(parts[1]))
    return header, payload, parts


# ---------------------------------------------------------------------------
# VULNERABLE verification. Three separate mistakes:
#   1. it trusts the algorithm named in the header, including "none"
#   2. for "none" it accepts the token with no signature at all
#   3. it never checks the expiry
# ---------------------------------------------------------------------------
def verify_vulnerable(token):
    header, payload, parts = decode_parts(token)
    alg = header.get("alg")
    if alg == "none":
        return payload                       # mistake 1 and 2
    if alg == "HS256":
        sig = b64u_dec(parts[2])
        expected = _hs256(f"{parts[0]}.{parts[1]}".encode(), HS_SECRET)
        if hmac.compare_digest(sig, expected):
            return payload                   # mistake 3: no expiry check
        raise JWTError("bad signature")
    raise JWTError(f"unexpected alg {alg}")


# ---------------------------------------------------------------------------
# SECURE verification:
#   1. the algorithm is pinned to HS256, so "none" and anything else is refused
#   2. the signature must be present and correct
#   3. the expiry is enforced
# (A strong secret is also required, which is a server config, not shown here.)
# ---------------------------------------------------------------------------
def verify_secure(token):
    header, payload, parts = decode_parts(token)
    if header.get("alg") != "HS256":
        raise JWTError("algorithm not allowed")
    if len(parts) != 3 or not parts[2]:
        raise JWTError("missing signature")
    sig = b64u_dec(parts[2])
    expected = _hs256(f"{parts[0]}.{parts[1]}".encode(), HS_SECRET)
    if not hmac.compare_digest(sig, expected):
        raise JWTError("bad signature")
    if payload.get("exp", 0) < time.time():
        raise JWTError("token expired")
    return payload


def verify(token, mode):
    return verify_secure(token) if mode == "secure" else verify_vulnerable(token)


# ---------------------------------------------------------------------------
# Attacker helpers, used by attacks.py to forge tokens.
# ---------------------------------------------------------------------------
def forge_none(sub, role):
    """A token with alg none and no signature."""
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": sub, "role": role, "exp": int(time.time()) + 3600}
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def forge_hs256(sub, role, secret, exp_offset=3600):
    """A properly signed token, once the attacker knows the secret."""
    return issue(sub, role, ttl=exp_offset, secret=secret)
