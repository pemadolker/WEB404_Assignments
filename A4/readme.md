# Druk Bank, CSRF Lab

A small online banking app for the Software Security practical "Create a CSRF
vulnerable form and then implement CSRF tokens to prevent attacks". It comes
with a separate attacker site that forges requests at the bank.

Insecure on purpose. Run only on your own machine, on localhost.

## Files

- `app.py` - the bank, with vulnerable and secure transfer handlers (port 5003)
- `attacker.py` - the malicious site that forges requests (port 5004)
- `static/style.css` - the bank interface styling
- `attacks.py` - shows the attack and the fix at the request level
- `LAB_REPORT.docx` / `.pdf` / `.md` - the report (submit the docx)
- `RECREATE_STEPS.md` - how to run it and take your own screenshots
- `attack_output.txt` - saved output of a real run
- `screenshots/` - the screenshots used in the report

## Setup

```
pip install flask requests
```

On Kali, use a venv first: `python3 -m venv venv && source venv/bin/activate && pip install flask requests`

## Run

Two terminals:

```
python3 app.py        # the bank, http://127.0.0.1:5003
python3 attacker.py   # the attacker, http://127.0.0.1:5004
```

Log into the bank as pema / pema123. Then, in the same browser, open the
attacker site at http://127.0.0.1:5004/ and watch your balance get moved to
mallory. Switch the bank to Secure mode and try again to see it blocked.

To see the whole thing at the request level: `python3 attacks.py`

Use 127.0.0.1 for both sites, not localhost, or the cookie will not line up.

## What it covers

- Forged POST through an auto submitting form
- Forged GET through an image tag (the bank wrongly accepts GET)
- Why the login cookie alone is not proof of intent
- The fix: a synchronizer CSRF token, plus SameSite, Origin checks and POST only
  actions as extra layers
