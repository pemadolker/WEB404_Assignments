"""
app.py  -  Zorig Portal
A staff and student portal that uses JWTs for authentication. It is a normal
looking portal; the JWT handling flaws are real but not advertised. The attacks
and the secure handling are documented in the lab report.

When you sign in, the server issues a signed JWT and stores it in a cookie.
Every page reads that token to decide who you are. The admin area needs role
admin. A normal account is not admin, so the attacks are about forging a token
that claims role admin without an admin login.

The token verifier runs in two modes used by the report to show the before and
after: the default trusts the algorithm in the token and ignores expiry, while
the hardened mode pins the algorithm, checks the signature and checks expiry.
The mode is an internal setting, not shown in the interface.

WARNING: insecure on purpose. Run only on localhost.
"""

from flask import (Flask, request, redirect, url_for, render_template_string,
                   make_response)
import tokens as T

app = Flask(__name__)

# Both are ordinary accounts. There is an admin (role admin) but nobody here
# knows its password; the point of the lab is to forge admin, not log in as it.
USERS = {"pema.dolker": "Pema@2026", "sonam.wangmo": "sonam456"}
NAMES = {"pema.dolker": "Pema Dolker", "sonam.wangmo": "Sonam Wangmo",
         "ashis.chettri": "Ashis Chettri"}


def who(username):
    return NAMES.get(username, username)


def get_mode():
    m = request.cookies.get("verify", "vulnerable")
    return m if m in ("vulnerable", "secure") else "vulnerable"


SHELL = """
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} - Zorig Portal</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}"></head><body>
<div class="topbar">
  <div class="brand"><span class="sq"></span><div>Zorig<span>Portal</span></div></div>
  <div class="right">
    {% if name %}<a href="/">Home</a><a href="/admin">Admin</a>
      <span class="me">{{ name }}</span><a href="/logout">Sign out</a>
    {% endif %}
  </div>
</div>
<div class="wrap">{{ body|safe }}</div>
<footer>&copy; 2026 Zorig Portal &middot; College of Science and Technology</footer>
</body></html>
"""


def page(title, name, body):
    return render_template_string(SHELL, title=title, name=name, body=body)


LOGIN = """
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in - Zorig Portal</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}"></head><body>
<div class="login-wrap"><div class="panel">
  <div class="brand" style="margin-bottom:16px"><span class="sq"></span>
    <div>Zorig<span>Portal</span></div></div>
  {% if error %}<div class="result deny">{{ error }}</div>{% endif %}
  <form method="post">
    <label>username</label><input type="text" name="username" placeholder="firstname.lastname">
    <label style="margin-top:12px">password</label>
    <input type="password" name="password" placeholder="password">
    <button class="btn" style="width:100%">Sign in</button>
  </form>
</div></div></body></html>
"""


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
    # internal setting used by the report; not linked anywhere in the interface
    resp = make_response(redirect(request.referrer or url_for("dashboard")))
    resp.set_cookie("verify", "secure" if m == "secure" else "vulnerable")
    return resp


@app.route("/")
def dashboard():
    token = request.cookies.get("token", "")
    if not token:
        return redirect(url_for("login"))
    try:
        claims = T.verify(token, get_mode())
    except T.JWTError:
        return redirect(url_for("login"))
    name = who(claims.get("sub", "?"))
    role = claims.get("role", "user")
    body = f"""
    <h1 class="page">Welcome, {name}</h1>
    <p class="sub">You are signed in to the Zorig Portal.</p>
    <div class="row">
      <div class="panel"><h2>Your profile</h2>
        <p class="kv">name: <b>{name}</b></p>
        <p class="kv">username: <b>{claims.get('sub','?')}</b></p>
        <p class="kv">access level: <b>{role}</b></p>
      </div>
      <div class="panel"><h2>Quick links</h2>
        <p class="kv"><a href="/admin">Administration &rarr;</a></p>
        <p class="kv"><a href="/">My courses</a></p>
        <p class="kv"><a href="/">Results</a></p>
      </div>
    </div>
    """
    return page("Home", name, body)


@app.route("/admin")
def admin():
    token = request.cookies.get("token", "")
    if not token:
        return redirect(url_for("login"))
    try:
        claims = T.verify(token, get_mode())
    except T.JWTError as e:
        return page("Admin", None,
                    f"<div class='result deny'>Access denied. {e}.</div>"
                    "<p class='sub'>The administration area requires a valid "
                    "staff token.</p>")
    name = who(claims.get("sub", "?"))
    if claims.get("role") != "admin":
        return page("Admin", name,
                    f"<div class='result deny'>Access denied. Your access level "
                    f"is '{claims.get('role')}', not administrator.</div>")
    body = """
    <div class="result ok">Access granted. Administration area.</div>
    <div class="adminpanel">
      <h1>Administration</h1>
      <p class="muted">Staff only. Manage portal accounts and records.</p>
      <ul class="userlist">
        <li><span>Ashis Chettri</span><span>ashis.chettri &middot; admin</span></li>
        <li><span>Pema Dolker</span><span>pema.dolker &middot; student</span></li>
        <li><span>Sonam Wangmo</span><span>sonam.wangmo &middot; student</span></li>
      </ul>
      <div class="danger-zone">Danger zone: reset any account, edit results,
      rotate the signing key.</div>
    </div>
    """
    return page("Admin", name, body)


@app.route("/api/whoami")
def whoami():
    token = (request.headers.get("Authorization", "").replace("Bearer ", "")
             or request.cookies.get("token", ""))
    mode = request.args.get("mode", "vulnerable")
    try:
        claims = T.verify(token, mode)
        return {"ok": True, "sub": claims.get("sub"), "role": claims.get("role"),
                "is_admin": claims.get("role") == "admin"}
    except T.JWTError as e:
        return {"ok": False, "error": str(e)}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5005, debug=False)
