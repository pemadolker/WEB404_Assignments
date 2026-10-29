"""
app.py  -  NetGuard Tools
A server operations console. It is a normal looking admin panel; the command
injection flaws are real but not advertised anywhere, as on a genuine
vulnerable tool. The attacks and fixes are documented in the lab report.

Tools:
  Host lookup  - resolves a hostname to an IP. Its output is shown (in band).
  Backup       - archives a folder. It only says done (blind).

Each tool has a hardened counterpart under /secure/ that the report uses to show
the before and after. The vulnerable routes build a command STRING and run it
with shell=True; the secure routes pass an argument LIST with shell=False plus
input validation.

WARNING: insecure on purpose. Run only on localhost.
"""

from flask import Flask, request, render_template_string
import subprocess
import re
import os

app = Flask(__name__)
APPDATA = os.path.join(os.path.dirname(__file__), "appdata")


SHELL = """
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} - NetGuard</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head><body>
<div class="layout">
  <aside class="side">
    <div class="brand"><span class="sq"></span> NetGuard</div>
    <div class="grp">Operations</div>
    <a href="/lookup" class="{{ 'active' if active=='lookup' else '' }}">
      <span class="dotm"></span> Host lookup</a>
    <a href="/backup" class="{{ 'active' if active=='backup' else '' }}">
      <span class="dotm"></span> Backup</a>
    <div class="grp">System</div>
    <a href="/lookup"><span class="dotm"></span> Nodes</a>
    <a href="/lookup"><span class="dotm"></span> Logs</a>
    <div class="foot">NetGuard Server Console v2.4<br>node cst-web-01</div>
  </aside>
  <div class="main">
    <div class="topbar">
      <div class="crumb">Operations / {{ title }}</div>
      <div class="status"><span class="live"></span> node: cst-web-01 &middot; connected</div>
    </div>
    <div class="wrap">{{ body|safe }}</div>
  </div>
</div>
</body></html>
"""


def page(title, active, body):
    return render_template_string(SHELL, title=title, active=active, body=body)


@app.route("/")
def home():
    return page("Host lookup", "lookup", lookup_body("", ""))


# ===========================================================================
# HOST LOOKUP  ->  in band command injection
# ===========================================================================

def lookup_body(host, result):
    return f"""
    <h1 class="page">Host lookup</h1>
    <p class="sub">Resolve a hostname to its IP address on this node.</p>
    <div class="panel">
      <h2>Resolve a host</h2>
      <p class="hint">Enter a hostname or IP, for example <code>localhost</code>.</p>
      <form method="get">
        <div class="field">
          <input name="host" placeholder="hostname or IP" value="{host}">
          <button>Look up</button>
        </div>
      </form>
    </div>
    {result}
    """


@app.route("/lookup")
def lookup():
    host = request.args.get("host", "")
    result = ""
    if host:
        # VULNERABLE: host pasted into a command string handed to the shell.
        command = f"getent hosts {host}"
        try:
            out = subprocess.run(command, shell=True, capture_output=True,
                                 text=True, timeout=10)
            combined = (out.stdout or "") + (out.stderr or "")
            if not combined.strip():
                combined = "(no results)"
            result = f"<pre>{combined}</pre>"
        except subprocess.TimeoutExpired:
            result = "<div class='box bad'>Request timed out</div>"
    return page("Host lookup", "lookup", lookup_body(host, result))


@app.route("/secure/lookup")
def secure_lookup():
    host = request.args.get("host", "")
    result = ""
    if host:
        # SECURE layer 1: allowlist of hostname characters.
        if not re.fullmatch(r"[A-Za-z0-9.\-]+", host):
            result = "<div class='box bad'>Invalid host. Rejected.</div>"
        else:
            # SECURE layer 2: no shell, arguments as a list.
            try:
                out = subprocess.run(["getent", "hosts", host], shell=False,
                                     capture_output=True, text=True, timeout=10)
                combined = (out.stdout or "") + (out.stderr or "")
                if not combined.strip():
                    combined = "(no results)"
                result = f"<pre>{combined}</pre>"
            except subprocess.TimeoutExpired:
                result = "<div class='box bad'>Request timed out</div>"
    return page("Host lookup", "lookup", lookup_body(host, result))


# ===========================================================================
# BACKUP  ->  blind command injection
# ===========================================================================

def backup_body(label, result):
    return f"""
    <h1 class="page">Backup</h1>
    <p class="sub">Archive a folder under appdata. This tool reports only that it
    finished.</p>
    <div class="panel">
      <h2>Create a backup</h2>
      <p class="hint">Enter a folder under appdata, for example <code>.</code></p>
      <form method="get">
        <div class="field">
          <input name="label" placeholder="folder under appdata" value="{label}">
          <button>Back up</button>
        </div>
      </form>
    </div>
    {result}
    """


@app.route("/backup")
def backup():
    label = request.args.get("label", "")
    result = ""
    if label:
        # VULNERABLE: label pasted into a shell command, output discarded (blind).
        command = f"tar czf /tmp/lab-backup.tgz appdata/{label}"
        try:
            subprocess.run(command, shell=True, capture_output=True,
                           text=True, timeout=30)
            result = "<div class='box ok'>Backup complete</div>"
        except subprocess.TimeoutExpired:
            result = "<div class='box bad'>Backup timed out</div>"
    return page("Backup", "backup", backup_body(label, result))


@app.route("/secure/backup")
def secure_backup():
    label = request.args.get("label", "")
    result = ""
    if label:
        if not re.fullmatch(r"[A-Za-z0-9_./\-]+", label) or ".." in label:
            result = "<div class='box bad'>Invalid label. Rejected.</div>"
        else:
            target = os.path.join("appdata", label)
            try:
                subprocess.run(["tar", "czf", "/tmp/lab-backup.tgz", target],
                               shell=False, capture_output=True, text=True, timeout=30)
                result = "<div class='box ok'>Backup complete</div>"
            except subprocess.TimeoutExpired:
                result = "<div class='box bad'>Backup timed out</div>"
    return page("Backup", "backup", backup_body(label, result))


if __name__ == "__main__":
    for f in ["/tmp/cmdi_proof.txt", "/tmp/cmdi_sub.txt", "/tmp/lab-backup.tgz"]:
        if os.path.exists(f):
            os.remove(f)
    app.run(host="127.0.0.1", port=5001, debug=False)
