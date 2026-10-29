# Zorig Console, JWT Lab

A small account console that uses JSON Web Tokens, for the Software Security
practical "Develop a JWT based authentication system, demonstrate common JWT
attacks, and implement secure JWT handling". The goal in the lab is to reach the
admin area as a normal user, by forging tokens.

Insecure on purpose. Run only on your own machine, on localhost.

## Files

- `app.py` - the console, with vulnerable and secure verify modes (port 5005)
- `tokens.py` - a small, readable JWT implementation (issue, verify, forge)
- `static/style.css` - the console styling
- `attacks.py` - runs all four attacks against both verifiers
- `LAB_REPORT.docx` / `.pdf` / `.md` - the report (submit the docx)
- `RECREATE_STEPS.md` - how to run it and take your own screenshots
- `attack_output.txt` - saved output of a real run
- `screenshots/` - the screenshots used in the report

## Setup

```
pip install flask requests cryptography
```

On Kali, use a venv: `python3 -m venv venv && source venv/bin/activate && pip install flask requests cryptography`

## Run

```
python3 app.py        # http://127.0.0.1:5005
```

Log in as alice / alice123. Use the token console on the dashboard to paste a
forged token and try to reach the admin area. Switch to secure mode to see the
forged tokens rejected.

To see all the attacks at once: `python3 attacks.py`

## Attacks covered

1. alg none, an unsigned token that claims role admin
2. Expired token still accepted (no expiry check)
3. Weak signing secret cracked by brute force, then valid admin tokens forged
4. Algorithm confusion, RS256 downgraded to HS256 using the public key

## Secure handling

Pin the algorithm (reject none and reject a swapped algorithm), always verify
the signature, enforce the expiry, and use a long random secret. The first three
are in the secure verifier; the last is why the brute force attack still matters.
