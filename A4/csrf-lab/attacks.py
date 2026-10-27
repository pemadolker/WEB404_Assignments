"""
attacks.py
Shows the CSRF flaw at the request level, and shows the token stopping it.

This script plays the part of the victim's browser. It logs into the bank once,
which gives it the session cookie, and then it fires forged requests at the
bank exactly the way a booby trapped page would, carrying only that cookie and
no CSRF token. The point is to show what the server accepts.

Start both servers first:  python3 app.py   and   python3 attacker.py
Then run:                   python3 attacks.py
"""

import requests
import re

BANK = "http://127.0.0.1:5003"


def banner(n, title):
    print()
    print("=" * 72)
    print(f"  ATTACK {n}: {title}")
    print("=" * 72)


def line():
    print("-" * 72)


def balances(s):
    return s.get(f"{BANK}/debug/balances").json()


# The victim's browser: logs in, holds the cookie for the rest of the script.
victim = requests.Session()
victim.post(f"{BANK}/login", data={"username": "pema", "password": "pema123"})
print("Victim pema is logged in. The session cookie is now held by the browser.")
print("Starting balances:", balances(victim))


def attack_post_no_token():
    banner(1, "Forged POST with no CSRF token (vulnerable /transfer)")
    print("A page on another site auto-submits this form. The browser attaches")
    print("the bank cookie on its own. There is no CSRF token anywhere.")
    line()
    before = balances(victim)
    # note: we even send a foreign Origin and Referer to show they are not checked
    victim.post(f"{BANK}/transfer",
                data={"to": "mallory", "amount": 20000},
                headers={"Origin": "http://evil.example",
                         "Referer": "http://evil.example/prize"})
    after = balances(victim)
    print("before:", before)
    print("after :", after, " <- Nu 20,000 moved to mallory with a forged request")


def attack_get_image():
    banner(2, "Forged GET through an image tag (vulnerable /transfer)")
    print("The bank accepts GET for transfers, so <img src=.../transfer?...>")
    print("fires it just by loading. No form and no script are needed.")
    line()
    before = balances(victim)
    victim.get(f"{BANK}/transfer", params={"to": "mallory", "amount": 5000})
    after = balances(victim)
    print("before:", before)
    print("after :", after, " <- Nu 5,000 moved just by loading an image URL")


def attack_secure_no_token():
    banner(3, "Same forged request against the secure endpoint")
    print("Now the forged POST hits /secure/transfer, which demands the token.")
    line()
    before = balances(victim)
    r = victim.post(f"{BANK}/secure/transfer",
                    data={"to": "mallory", "amount": 20000},
                    allow_redirects=True)
    after = balances(victim)
    msg = re.search(r"flash[^>]*>([^<]+)</div>", r.text)
    print("before:", before)
    print("after :", after, " <- unchanged, the forged request was blocked")

    print()
    print("Trying again with a made up token:")
    before = balances(victim)
    victim.post(f"{BANK}/secure/transfer",
                data={"to": "mallory", "amount": 20000,
                      "csrf_token": "a-guessed-token"})
    print("after :", balances(victim), " <- still blocked, the guess is wrong")


def legit_secure_transfer():
    banner(4, "A genuine transfer through the secure form still works")
    print("The real page includes the correct token, so a real transfer by the")
    print("account owner goes through normally.")
    line()
    # read the secure dashboard and scrape the token out of the hidden field
    page = victim.get(f"{BANK}/?mode=secure").text
    token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page).group(1)
    print("token read from the owner's own page:", token[:16], "...")
    before = balances(victim)
    victim.post(f"{BANK}/secure/transfer",
                data={"to": "mallory", "amount": 1000, "csrf_token": token})
    after = balances(victim)
    print("before:", before)
    print("after :", after, " <- Nu 1,000 sent, accepted because the token matched")


if __name__ == "__main__":
    attack_post_no_token()
    attack_get_image()
    attack_secure_no_token()
    legit_secure_transfer()
    print()
    line()
    print("Summary: the vulnerable endpoint moved money on any request that")
    print("carried the login cookie. The secure endpoint moved money only when")
    print("the correct CSRF token was present, which a forged cross site request")
    print("cannot obtain. Restart app.py to reset balances.")
