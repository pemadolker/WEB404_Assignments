"""
app.py  -  Druk Bank
A small online banking app used to demonstrate Cross Site Request Forgery
(CSRF) and then the token that defends against it.

A CSRF attack abuses one simple browser behaviour: when the browser sends a
request to a site, it automatically attaches that site's cookies, including the
login session cookie, no matter which page started the request. So if a logged
in user can be made to fire a request at the bank (by visiting a booby trapped
page), the bank sees a fully logged in request and carries it out. The user
never meant to send it.

The dashboard has two modes:
  Vulnerable mode -> the transfer form posts to /transfer, which checks nothing
                     beyond the login cookie, and even accepts GET.
  Secure mode     -> the form posts to /secure/transfer, which requires a secret
                     CSRF token that only the real page could have known.

WARNING: insecure on purpose. Run only on localhost.
"""

from flask import (Flask, request, redirect, url_for, render_template_string,
                   session, abort)
import secrets

app = Flask(__name__)
app.secret_key = "lab-demo-key-not-for-real-use"
# Lax is the modern default. It blocks cross SITE sends. Note that two ports on
# localhost are the SAME site, so the attacker page (another port) is same site
# here and the cookie still flows. That is why the token, not SameSite, is the
# defence we demonstrate. The report explains this.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# In memory accounts, reset whenever the server restarts.
def fresh_accounts():
    return {
        "pema":    {"pw": "pema123",    "name": "Pema Dolker", "balance": 50000,
                    "email": "pema@drukbank.bt", "activity": []},
        "mallory": {"pw": "mallory123", "name": "Mallory",     "balance": 0,
                    "email": "mallory@evil.bt", "activity": []},
    }
ACCOUNTS = fresh_accounts()


def current_user():
    u = session.get("user")
    return u if u in ACCOUNTS else None


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

LOGIN = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Druk Bank - Online Banking</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}"></head><body>
<div class="login-wrap"><div class="login-card">
  <h1>Druk Bank</h1>
  <p class="muted">Sign in to your online banking.</p>
  {% if error %}<div class="flash warn">{{ error }}</div>{% endif %}
  <form method="post">
    <label>Username</label><input type="text" name="username" placeholder="username">
    <label>Password</label><input type="password" name="password" placeholder="password">
    <button class="btn full">Sign in</button>
  </form>
  <p class="muted" style="margin-top:14px">Forgot your password? Visit any
  branch with your CID.</p>
</div></div></body></html>
"""

DASH = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Druk Bank</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}"></head><body>
<div class="topbar">
  <div class="brand"><span class="logo"></span> Druk Bank</div>
  <div class="who">{{ acct.name }} &nbsp;|&nbsp; <a href="{{ url_for('logout') }}">sign out</a></div>
</div>
<div class="wrap">
  {% if flash %}<div class="flash {{ flash_kind }}">{{ flash }}</div>{% endif %}

  <div class="cols">
    <div class="card">
      <div class="balance-label">Available balance</div>
      <div class="balance"><span class="cur">Nu.</span>{{ '{:,}'.format(acct.balance) }}</div>
      <div class="acct">Account 100-{{ user }}-01 &middot; {{ acct.email }}</div>

      <h2 style="margin-top:26px">Transfer money</h2>
      {% if mode=='vulnerable' %}
      <form method="post" action="/transfer">
      {% else %}
      <form method="post" action="/secure/transfer">
        <input type="hidden" name="csrf_token" value="{{ csrf }}">
      {% endif %}
        <label>To account</label>
        <input type="text" name="to" placeholder="recipient username">
        <label>Amount (Nu.)</label>
        <input type="number" name="amount" placeholder="0">
        <button class="btn">Send money</button>
      </form>
    </div>

    <div class="card">
      <h2>Recent activity</h2>
      {% if acct.activity %}
      <ul class="activity">
        {% for a in acct.activity %}
        <li><span>{{ a.text }}</span>
          <span class="{{ a.dir }}">{{ a.amt }}</span></li>
        {% endfor %}
      </ul>
      {% else %}
      <p class="muted">No transfers yet.</p>
      {% endif %}
    </div>
  </div>
</div>
<footer>&copy; 2026 Druk Bank Ltd. Member, Royal Monetary Authority of Bhutan.</footer>
</body></html>
"""


def do_transfer(sender, to, amount):
    """Move money. Returns (ok, message)."""
    if to not in ACCOUNTS:
        return False, f"No account named {to}."
    try:
        amount = int(amount)
    except (TypeError, ValueError):
        return False, "Invalid amount."
    if amount <= 0:
        return False, "Amount must be positive."
    if ACCOUNTS[sender]["balance"] < amount:
        return False, "Insufficient funds."
    ACCOUNTS[sender]["balance"] -= amount
    ACCOUNTS[to]["balance"] += amount
    ACCOUNTS[sender]["activity"].insert(0,
        {"text": f"Sent to {to}", "amt": f"- Nu. {amount:,}", "dir": "out"})
    ACCOUNTS[to]["activity"].insert(0,
        {"text": f"Received from {sender}", "amt": f"+ Nu. {amount:,}", "dir": "in"})
    return True, f"Transferred Nu. {amount:,} to {to}."


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u in ACCOUNTS and ACCOUNTS[u]["pw"] == p:
            session["user"] = u
            session["csrf"] = secrets.token_hex(32)
            return redirect(url_for("dashboard"))
        error = "Wrong username or password."
    return render_template_string(LOGIN, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    mode = request.args.get("mode", "vulnerable")
    if mode not in ("vulnerable", "secure"):
        mode = "vulnerable"
    return render_template_string(
        DASH, user=user, acct=ACCOUNTS[user], mode=mode,
        csrf=session.get("csrf", ""),
        flash=request.args.get("flash", ""),
        flash_kind=request.args.get("kind", "good"))


# ---------------------------------------------------------------------------
# VULNERABLE transfer: trusts the session cookie only, and accepts GET too.
# ---------------------------------------------------------------------------

@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    src = request.values  # values = args + form, so GET or POST both work
    ok, msg = do_transfer(user, src.get("to", ""), src.get("amount", 0))
    return redirect(url_for("dashboard", mode="vulnerable", flash=msg,
                            kind="good" if ok else "warn"))


# ---------------------------------------------------------------------------
# SECURE transfer: POST only, and the CSRF token must match the session.
# ---------------------------------------------------------------------------

@app.route("/secure/transfer", methods=["POST"])
def secure_transfer():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # The defence: a forged request from another site cannot read this token.
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("csrf"):
        return redirect(url_for("dashboard", mode="secure",
            flash="Transfer blocked: missing or invalid CSRF token.",
            kind="warn"))
    ok, msg = do_transfer(user, request.form.get("to", ""),
                          request.form.get("amount", 0))
    return redirect(url_for("dashboard", mode="secure", flash=msg,
                            kind="good" if ok else "warn"))


# read only helper for the attack script to check balances
@app.route("/debug/balances")
def debug_balances():
    import json
    return app.response_class(
        json.dumps({u: ACCOUNTS[u]["balance"] for u in ACCOUNTS}),
        mimetype="application/json")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5003, debug=False)
