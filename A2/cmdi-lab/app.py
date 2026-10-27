"""
app.py  -  NetGuard Tools
A server operations console used to demonstrate OS command injection and then
the fixes for it.

It offers two command line style tools that a real admin panel might have:

  Host lookup  - resolves a hostname to an IP. Its output IS shown, so it is an
                 in band target.
  Backup       - archives a folder. It only says "done", so it is a blind target.

Every tool exists twice. The normal version is at /lookup and /backup. The fixed
version is at /secure/lookup and /secure/backup. Both do the same job, so any
difference in behaviour comes only from how the command is run.

The difference that matters:
  Vulnerable routes build one command STRING and hand it to the shell
  (shell=True), so the shell interprets ;  &&  |  $( ) inside it and injected
  input becomes new commands.
  Secure routes pass the program and its arguments as a LIST with shell=False,
  so the input is only ever one argument, plus input validation on top.

WARNING: insecure on purpose. Run only on localhost.
"""

from flask import Flask, request, render_template_string
import subprocess
import re
import os

app = Flask(__name__)
APPDATA = os.path.join(os.path.dirname(__file__), "appdata")


# ---------------------------------------------------------------------------
# Shared console shell
# ---------------------------------------------------------------------------

SHELL = """
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} - NetGuard Tools</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head><body>
<div class="layout">
  <aside class="side">
    <div class="brand"><span class="sq"></span> NetGuard</div>
    <div class="grp">Tools</div>
    <a href="/lookup" class="{{ 'active vuln' if active=='lookup' else '' }}">
      <span class="dotm"></span> Host lookup</a>
    <a href="/backup" class="{{ 'active vuln' if active=='backup' else '' }}">
      <span class="dotm"></span> Backup</a>
    <div class="grp">Secure versions</div>
    <a href="/secure/lookup" class="{{ 'active' if active=='slookup' else '' }}">
      <span class="dotm"></span> Host lookup</a>
    <a href="/secure/backup" class="{{ 'active' if active=='sbackup' else '' }}">
      <span class="dotm"></span> Backup</a>
    <div class="foot">NetGuard Tools is a teaching app for the command
      injection practical. Do not deploy it.</div>
  </aside>
  <div class="main">
    <div class="topbar">
      <div class="crumb">Operations / {{ title }}</div>
      <div class="status"><span class="live"></span> node: web-01 &middot; connected</div>
    </div>
    <div class="wrap">{{ body|safe }}</div>
  </div>
</div>
</body></html>
"""


def page(title, active, body):
    return render_template_string(SHELL, title=title, active=active, body=body)


def strip(kind, other_path, other_label):
    pill = (f"<span class='pill {'vuln' if kind=='vulnerable' else 'safe'}'>"
            f"{'vulnerable tool' if kind=='vulnerable' else 'secure tool'}</span>")
    return (f"<div class='modestrip'>{pill} "
            f"<a href='{other_path}'>switch to the {other_label}</a></div>")


@app.route("/")
def home():
    return page("Host lookup", "lookup", lookup_body("", "",
                strip("vulnerable", "/secure/lookup", "secure version")))


# ===========================================================================
# HOST LOOKUP  ->  in band command injection
# ===========================================================================

def lookup_body(host, result, strip_html):
    return f"""
    <h1 class="page">Host lookup</h1>
    <p class="sub">Resolve a hostname to its IP address on this node.</p>
    {strip_html}
    <div class="panel">
      <h2>Resolve a host</h2>
      <p class="hint">Normal use: enter <code>localhost</code>.</p>
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
        # VULNERABLE: the host is pasted into a command string handed to the
        # shell, which interprets ; && | $( ) etc.
        command = f"getent hosts {host}"
        try:
            out = subprocess.run(command, shell=True, capture_output=True,
                                 text=True, timeout=10)
            combined = (out.stdout or "") + (out.stderr or "")
            if not combined.strip():
                combined = "(no output)"
            result = (f"<div class='box'>Command: <code>{command}</code></div>"
                      f"<pre>{combined}</pre>")
        except subprocess.TimeoutExpired:
            result = "<div class='box bad'>Command timed out</div>"
    return page("Host lookup", "lookup",
                lookup_body(host, result,
                            strip("vulnerable", "/secure/lookup", "secure version")))


@app.route("/secure/lookup")
def secure_lookup():
    host = request.args.get("host", "")
    result = ""
    if host:
        # SECURE layer 1: allowlist. A hostname is only letters, digits, dots
        # and hyphens. Anything else is refused before anything runs.
        if not re.fullmatch(r"[A-Za-z0-9.\-]+", host):
            result = "<div class='box bad'>Invalid host. Rejected.</div>"
        else:
            # SECURE layer 2: no shell, arguments as a list.
            try:
                out = subprocess.run(["getent", "hosts", host], shell=False,
                                     capture_output=True, text=True, timeout=10)
                combined = (out.stdout or "") + (out.stderr or "")
                if not combined.strip():
                    combined = "(no output)"
                result = f"<pre>{combined}</pre>"
            except subprocess.TimeoutExpired:
                result = "<div class='box bad'>Command timed out</div>"
    return page("Host lookup (secure)", "slookup",
                lookup_body(host, result,
                            strip("secure", "/lookup", "vulnerable version")))


# ===========================================================================
# BACKUP  ->  blind command injection
# ===========================================================================

def backup_body(label, result, strip_html):
    return f"""
    <h1 class="page">Backup</h1>
    <p class="sub">Archive a folder under appdata. This tool reports only that it
    finished, it never shows command output.</p>
    {strip_html}
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
        # VULNERABLE: label pasted into a shell command. Output is thrown away,
        # so any injection here is blind.
        command = f"tar czf /tmp/lab-backup.tgz appdata/{label}"
        try:
            subprocess.run(command, shell=True, capture_output=True,
                           text=True, timeout=30)
            result = ("<div class='box ok'>Backup complete</div>"
                      f"<div class='box'>Command: <code>{command}</code></div>")
        except subprocess.TimeoutExpired:
            result = "<div class='box bad'>Backup timed out</div>"
    return page("Backup", "backup",
                backup_body(label, result,
                            strip("vulnerable", "/secure/backup", "secure version")))


@app.route("/secure/backup")
def secure_backup():
    label = request.args.get("label", "")
    result = ""
    if label:
        # SECURE layer 1: allowlist of safe path characters.
        if not re.fullmatch(r"[A-Za-z0-9_./\-]+", label) or ".." in label:
            result = "<div class='box bad'>Invalid label. Rejected.</div>"
        else:
            # SECURE layer 2: no shell, arguments as a list.
            target = os.path.join("appdata", label)
            try:
                subprocess.run(["tar", "czf", "/tmp/lab-backup.tgz", target],
                               shell=False, capture_output=True, text=True, timeout=30)
                result = "<div class='box ok'>Backup complete</div>"
            except subprocess.TimeoutExpired:
                result = "<div class='box bad'>Backup timed out</div>"
    return page("Backup (secure)", "sbackup",
                backup_body(label, result,
                            strip("secure", "/backup", "vulnerable version")))


if __name__ == "__main__":
    for f in ["/tmp/cmdi_proof.txt", "/tmp/cmdi_sub.txt", "/tmp/lab-backup.tgz"]:
        if os.path.exists(f):
            os.remove(f)
    app.run(host="127.0.0.1", port=5001, debug=False)
