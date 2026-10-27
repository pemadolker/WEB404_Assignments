"""
app.py  -  Zorig Console
A small account console that uses JWTs for authentication, to demonstrate common
JWT attacks and then secure handling.

When you log in, the server gives you a signed JWT and stores it in a cookie.
Every page then reads that token to decide who you are and what you can see. The
admin area needs role admin. A normal user is not admin, so the attacks are all
about forging a token that claims role admin without knowing the admin password.

The verification mode is switched at the top:
  Vulnerable  ->  trusts the algorithm in the token header (including none),
                  and never checks expiry
  Secure      ->  pins the algorithm, checks the signature, checks expiry

There is a token console on the dashboard so you can paste any token and act as
it, which is exactly what an attacker does with a forged token.

WARNING: insecure on purpose. Run only on localhost.
"""

from flask import (Flask, request, redirect, url_for, render_template_string,
                   make_response)
import json
import tokens as T

app = Flask(__name__)

USERS = {"alice": "alice123", "bimal": "bimal123"}   # both are normal users
# There is an admin account, but nobody logging in here knows its password.
# That is the point: the attacker forges admin instead of logging in as admin.


def pretty(obj):
    return json.dumps(obj, indent=2)


def get_mode():
    m = request.cookies.get("mode", "vulnerable")
    return m if m in ("vulnerable", "secure") else "vulnerable"


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

LOGIN = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zorig Console</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}"></head><body>
<div class="login-wrap"><div class="panel">
  <div class="brand" style="margin-bottom:14px"><span class="sq"></span>
    <div>Zorig<span>Console</span></div></div>
  {% if error %}<div class="result deny">{{ error }}</div>{% endif %}
  <form method="post">
    <label>username</label><input type="text" name="username" value="alice">
    <label style="margin-top:12px">password</label>
    <input type="password" name="password" value="alice123">
    <button class="btn" style="width:100%">Sign in</button>
  </form>
  <p class="muted" style="margin-top:14px">Demo user: alice / alice123 (role
  user). Your goal in the lab is to reach the admin area without an admin
  login.</p>
</div></div></body></html>
"""

SHELL = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zorig Console</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}"></head><body>
<div class="topbar">
  <div class="brand"><span class="sq"></span><div>Zorig<span>Console</span></div></div>
  <div class="modeswitch">
    <a href="{{ url_for('set_mode', m='vulnerable') }}" class="{{ 'on-vuln' if mode=='vulnerable' else '' }}">vulnerable</a>
    <a href="{{ url_for('set_mode', m='secure') }}" class="{{ 'on-safe' if mode=='secure' else '' }}">secure</a>
  </div>
  <div class="right"><a href="/admin">admin area</a><a href="{{ url_for('logout') }}">sign out</a></div>
</div>
<div class="wrap">
{{ body|safe }}
</div>
<footer>Zorig Console is a teaching app for the JWT practical. Do not deploy it.
Verify mode: {{ mode }}.</footer>
</body></html>
"""


def render(body):
    return render_template_string(SHELL, body=body, mode=get_mode())


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if USERS.get(u) == p:
            token = T.issue(u, "user")
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie("token", token)
            resp.set_cookie("mode", "vulnerable")
            return resp
        error = "Wrong username or password."
    return render_template_string(LOGIN, error=error)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("token")
    return resp


@app.route("/mode/<m>")
def set_mode(m):
    resp = make_response(redirect(request.referrer or url_for("dashboard")))
    resp.set_cookie("mode", "secure" if m == "secure" else "vulnerable")
    return resp


@app.route("/use", methods=["POST"])
def use_token():
    token = request.form.get("token", "").strip()
    resp = make_response(redirect(url_for("dashboard")))
    resp.set_cookie("token", token)
    return resp


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    token = request.cookies.get("token", "")
    if not token:
        return redirect(url_for("login"))
    mode = get_mode()
    try:
        claims = T.verify(token, mode)
        valid = True
        note = ""
    except T.JWTError as e:
        claims = None
        valid = False
        note = str(e)

    # show the raw token parts so the structure is visible
    sub_display = "?"
    try:
        header, payload, parts = T.decode_parts(token)
        sub_display = payload.get("sub", "?")
        colored = (f"<span class='h'>{parts[0]}</span>."
                   f"<span class='p'>{parts[1]}</span>."
                   f"<span class='s'>{parts[2] if len(parts)>2 else ''}</span>")
        decoded = (f"header:  {pretty(header)}\n\npayload: {pretty(payload)}")
    except Exception:
        colored = token
        decoded = "(could not decode)"

    role = (claims or {}).get("role", "unknown") if valid else "unverified"
    badge = f"<span class='rolebadge {role if role in ('user','admin') else 'user'}'>role: {role}</span>"
    status = (f"<div class='result ok'>Token verified in {mode} mode. You are "
              f"'{(claims or {}).get('sub','?')}'.</div>" if valid else
              f"<div class='result deny'>Token rejected in {mode} mode: {note}</div>")

    body = f"""
    {status}
    <div class="row">
      <div class="panel">
        <h2>your session</h2>
        {badge}
        <p class="kv">subject: <b>{sub_display}</b></p>
        <p class="kv">this token is checked by the <b>{mode}</b> verifier</p>
        <p style="margin-top:14px"><a href="/admin">go to the admin area &rarr;</a></p>
      </div>
      <div class="panel">
        <h2>decoded token</h2>
        <pre class="jwt">{colored}</pre>
        <pre class="jwt" style="margin-top:10px">{decoded}</pre>
      </div>
    </div>
    <div class="panel">
      <h2>token console</h2>
      <p class="muted" style="margin-bottom:10px">Paste any token to act as it.
      This is what an attacker does with a forged token.</p>
      <form method="post" action="/use">
        <label>token</label>
        <textarea name="token">{token}</textarea>
        <button class="btn">Use this token</button>
      </form>
    </div>
    """
    return render(body)


@app.route("/admin")
def admin():
    token = request.cookies.get("token", "")
    if not token:
        return redirect(url_for("login"))
    mode = get_mode()
    try:
        claims = T.verify(token, mode)
    except T.JWTError as e:
        return render(f"<div class='result deny'>Access denied. Token rejected: "
                      f"{e}</div><p class='muted'>The admin area needs a valid "
                      f"token with role admin.</p>")

    if claims.get("role") != "admin":
        return render(f"<div class='result deny'>Access denied. Your role is "
                      f"'{claims.get('role')}', not admin.</div>")

    # role is admin: show the admin panel
    body = """
    <div class="result ok">Access granted. Welcome to the admin area.</div>
    <div class="adminpanel">
      <h1>Admin area</h1>
      <p class="muted">Full control of the console. Only role admin should ever
      see this.</p>
      <ul class="userlist">
        <li><span>alice</span><span>role: user</span></li>
        <li><span>bimal</span><span>role: user</span></li>
        <li><span>admin</span><span>role: admin</span></li>
      </ul>
      <div class="danger-zone">Danger zone: delete any user, read all data,
      rotate the signing key. If you can see this with a forged token, the auth
      is broken.</div>
    </div>
    """
    return render(body)


# A small JSON endpoint so the attack script can test a token quickly.
@app.route("/api/whoami")
def whoami():
    token = request.headers.get("Authorization", "").replace("Bearer ", "") \
        or request.cookies.get("token", "")
    mode = request.args.get("mode", "vulnerable")
    try:
        claims = T.verify(token, mode)
        return {"ok": True, "sub": claims.get("sub"), "role": claims.get("role"),
                "is_admin": claims.get("role") == "admin"}
    except T.JWTError as e:
        return {"ok": False, "error": str(e)}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5005, debug=False)
