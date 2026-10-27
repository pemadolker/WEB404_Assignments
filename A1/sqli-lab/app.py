"""
app.py  -  Norbu Electronics
A small online electronics store, used to demonstrate every common class of SQL
injection, with a secure version of each feature so the before and after can be
compared using the exact same payloads.

Every risky feature exists twice. The normal version is at a path like /login
and the fixed version is at /secure/login. The query logic is the only thing
that changes between them, so any difference in behaviour is caused by the
injection defence alone.

  /login     vulnerable     /secure/login     fixed   (auth bypass, error)
  /product   vulnerable     /secure/product   fixed   (UNION, numeric context)
  /search    vulnerable     /secure/search    fixed   (UNION, string context)
  /profile   vulnerable     /secure/profile   fixed   (boolean + time blind)
  /track     vulnerable     /secure/track     fixed   (stacked queries)
  /reset     vulnerable                               (second order)

The vulnerable routes paste user input straight into the SQL string. The secure
routes use parameterised queries, and input validation where it fits.

WARNING: insecure on purpose. Run only on localhost. Never deploy it.
"""

from flask import Flask, request, render_template_string, jsonify
import sqlite3
from database import init_db, get_connection

app = Flask(__name__)
init_db()   # rebuild the database on every start, so the lab is repeatable

IMG = {"keyboard": "keyboard", "mouse": "mouse", "monitor": "monitor",
       "webcam": "webcam"}


# ---------------------------------------------------------------------------
# Shared page shell (the polished storefront chrome)
# ---------------------------------------------------------------------------

SHELL = """
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} - Norbu Electronics</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head><body>
<div class="topbar">
  <div class="brand"><span class="dot"></span>
    <div>Norbu Electronics<small>Thimphu's online tech store</small></div></div>
  <div class="searchbar">
    <form method="get" action="/search">
      <input name="q" placeholder="Search products..." value="">
      <button>Search</button>
    </form>
  </div>
  <div class="topnav">
    <a href="/">Store</a>
    <a href="/login">Sign in</a>
    <a href="/cart" class="cart">Cart</a>
  </div>
</div>
<div class="wrap">
{{ body|safe }}
</div>
<footer>Norbu Electronics is a teaching app for the SQL injection practical.
Do not deploy it. Every feature has a secure version under /secure/.</footer>
</body></html>
"""


def page(title, body):
    return render_template_string(SHELL, title=title, body=body)


def mode_strip(kind, this_path, other_path, other_label):
    """The little vulnerable/secure indicator shown on each demo page."""
    pill = (f"<span class='pill {'vuln' if kind=='vulnerable' else 'safe'}'>"
            f"{'vulnerable endpoint' if kind=='vulnerable' else 'secure endpoint'}</span>")
    return (f"<div class='modestrip'>{pill} "
            f"<span>you are on <code>{this_path}</code></span> "
            f"<span>&middot;</span> <a href='{other_path}'>try the {other_label}</a></div>")


# ---------------------------------------------------------------------------
# Home: the storefront
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    conn = get_connection()
    rows = conn.execute("SELECT id, name, description, price FROM products").fetchall()
    conn.close()
    cards = ""
    for r in rows:
        img = IMG.get(r["name"].lower(), "keyboard")
        cards += f"""
        <div class="pcard">
          <a href="/product?id={r['id']}"><div class="ph">
            <img src="{{{{ url_for('static', filename='img/{img}.jpg') }}}}" alt="{r['name']}">
          </div></a>
          <div class="body">
            <div class="name">{r['name']}</div>
            <div class="desc">{r['description']}</div>
            <div class="foot"><span class="price">Nu. {int(r['price']):,}</span>
              <a class="view" href="/product?id={r['id']}">View &rarr;</a></div>
          </div>
        </div>"""
    body = f"""
    <div class="hero">
      <span class="tagpill">New arrivals this week</span>
      <h1>Gear up for the semester.</h1>
      <p>Keyboards, monitors and accessories, delivered across Thimphu. Sign in
      to track orders and save your cart.</p>
    </div>
    <div class="sectionhead"><h2>Popular products</h2>
      <span class="muted">{len(rows)} items</span></div>
    <div class="grid">{cards}</div>
    """
    # cards contain url_for template tags, so render once more
    return render_template_string(SHELL, title="Store",
                                  body=render_template_string(body))


@app.route("/cart")
def cart():
    return page("Cart", "<h1 class='page'>Your cart</h1>"
                "<div class='box'>Your cart is empty.</div>")


# ===========================================================================
# 1. LOGIN  ->  authentication bypass + error disclosure
# ===========================================================================

LOGIN_FORM = """
<h1 class="page">Sign in to your account</h1>
<p class="sub">Access your orders and saved items.</p>
{{ strip|safe }}
<div class="panel narrow">
  <form method="post">
    <label>Username</label>
    <input type="text" name="username" placeholder="your username">
    <label>Password</label>
    <input type="text" name="password" placeholder="your password">
    <button class="btn">Sign in</button>
  </form>
</div>
<p class="sub" style="margin-top:16px">Demo account: <code>pema</code> /
<code>pema123</code>.</p>
{{ result|safe }}
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    result = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABLE: user input pasted straight into the query.
        query = ("SELECT id, username, role FROM users "
                 f"WHERE username = '{username}' AND password = '{password}'")
        conn = get_connection()
        try:
            row = conn.execute(query).fetchone()
            if row:
                result = (f"<div class='box ok'>Logged in as <b>{row['username']}</b> "
                          f"(role: {row['role']})</div>")
            else:
                result = "<div class='box bad'>Invalid credentials</div>"
        except sqlite3.Error as e:
            result = f"<div class='box bad'>SQL error: {e}</div>"
        finally:
            conn.close()
        result += f"<div class='querylabel'>Query that ran</div><pre>{query}</pre>"

    strip = mode_strip("vulnerable", "/login", "/secure/login", "secure login")
    return page("Sign in", render_template_string(LOGIN_FORM, result=result, strip=strip))


@app.route("/secure/login", methods=["GET", "POST"])
def secure_login():
    result = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # SECURE: values are bound, never concatenated.
        query = ("SELECT id, username, role FROM users "
                 "WHERE username = ? AND password = ?")
        conn = get_connection()
        try:
            row = conn.execute(query, (username, password)).fetchone()
            if row:
                result = (f"<div class='box ok'>Logged in as <b>{row['username']}</b> "
                          f"(role: {row['role']})</div>")
            else:
                result = "<div class='box bad'>Invalid credentials</div>"
        except sqlite3.Error:
            result = "<div class='box bad'>Something went wrong</div>"
        finally:
            conn.close()
        result += ("<div class='querylabel'>Prepared statement</div>"
                   "<pre>SELECT id, username, role FROM users "
                   "WHERE username = ? AND password = ?</pre>")

    strip = mode_strip("secure", "/secure/login", "/login", "vulnerable login")
    return page("Sign in (secure)",
                render_template_string(LOGIN_FORM, result=result, strip=strip))


# ===========================================================================
# 2. PRODUCT BY ID  ->  UNION based (numeric context)
# ===========================================================================

def render_products(rows, columns):
    head = "".join(f"<th>{c}</th>" for c in columns)
    body = ""
    for r in rows:
        cells = "".join(f"<td>{r[i]}</td>" for i in range(len(columns)))
        body += f"<tr>{cells}</tr>"
    return f"<table><tr>{head}</tr>{body}</table>"


@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    # VULNERABLE: numeric id pasted in with no quotes and no validation.
    query = f"SELECT id, name, description, price FROM products WHERE id = {pid}"
    conn = get_connection()
    try:
        rows = conn.execute(query).fetchall()
        table = (render_products(rows, ["id", "name", "description", "price"])
                 if rows else "<div class='box'>No such product</div>")
    except sqlite3.Error as e:
        table = f"<div class='box bad'>SQL error: {e}</div>"
    finally:
        conn.close()

    strip = mode_strip("vulnerable", "/product", "/secure/product?id=1", "secure version")
    body = (f"<h1 class='page'>Product details</h1>"
            f"<p class='sub'>Showing product id = <code>{pid}</code></p>{strip}{table}"
            f"<div class='querylabel'>Query that ran</div><pre>{query}</pre>")
    return page("Product", body)


@app.route("/secure/product")
def secure_product():
    pid = request.args.get("id", "1")
    strip = mode_strip("secure", "/secure/product", "/product?id=1", "vulnerable version")
    # SECURE: an id must be an integer.
    if not pid.isdigit():
        return page("Product (secure)",
                    f"<h1 class='page'>Product details</h1>{strip}"
                    "<div class='box bad'>Invalid product id</div>")
    query = "SELECT id, name, description, price FROM products WHERE id = ?"
    conn = get_connection()
    try:
        rows = conn.execute(query, (int(pid),)).fetchall()
        table = (render_products(rows, ["id", "name", "description", "price"])
                 if rows else "<div class='box'>No such product</div>")
    except sqlite3.Error:
        table = "<div class='box bad'>Something went wrong</div>"
    finally:
        conn.close()
    body = (f"<h1 class='page'>Product details</h1>"
            f"<p class='sub'>Showing product id = <code>{pid}</code></p>{strip}{table}")
    return page("Product (secure)", body)


# ===========================================================================
# 3. SEARCH  ->  UNION based (string context, inside a LIKE)
# ===========================================================================

@app.route("/search")
def search():
    term = request.args.get("q", "")
    # VULNERABLE: search term pasted inside a quoted LIKE clause.
    query = ("SELECT id, name, description, price FROM products "
             f"WHERE name LIKE '%{term}%'")
    conn = get_connection()
    try:
        rows = conn.execute(query).fetchall()
        table = (render_products(rows, ["id", "name", "description", "price"])
                 if rows else "<div class='box'>No matches</div>")
    except sqlite3.Error as e:
        table = f"<div class='box bad'>SQL error: {e}</div>"
    finally:
        conn.close()
    strip = mode_strip("vulnerable", "/search", "/secure/search?q=key", "secure search")
    body = (f"<h1 class='page'>Search results</h1>"
            f"<p class='sub'>Results for <code>{term}</code></p>{strip}{table}"
            f"<div class='querylabel'>Query that ran</div><pre>{query}</pre>")
    return page("Search", body)


@app.route("/secure/search")
def secure_search():
    term = request.args.get("q", "")
    query = ("SELECT id, name, description, price FROM products WHERE name LIKE ?")
    conn = get_connection()
    try:
        rows = conn.execute(query, (f"%{term}%",)).fetchall()
        table = (render_products(rows, ["id", "name", "description", "price"])
                 if rows else "<div class='box'>No matches</div>")
    except sqlite3.Error:
        table = "<div class='box bad'>Something went wrong</div>"
    finally:
        conn.close()
    strip = mode_strip("secure", "/secure/search", "/search?q=key", "vulnerable search")
    body = (f"<h1 class='page'>Search results</h1>"
            f"<p class='sub'>Results for <code>{term}</code></p>{strip}{table}")
    return page("Search (secure)", body)


# ===========================================================================
# 4 and 5. PROFILE  ->  boolean blind + time based blind
# ===========================================================================

@app.route("/profile")
def profile():
    username = request.args.get("username", "")
    query = f"SELECT id FROM users WHERE username = '{username}'"
    conn = get_connection()
    try:
        row = conn.execute(query).fetchone()
        msg = ("<div class='box ok'>User exists</div>" if row
               else "<div class='box bad'>No such user</div>")
    except sqlite3.Error:
        msg = "<div class='box bad'>No such user</div>"
    finally:
        conn.close()
    strip = mode_strip("vulnerable", "/profile", "/secure/profile?username=admin", "secure version")
    return page("Username check",
                f"<h1 class='page'>Username availability</h1>"
                f"<p class='sub'>Checking username <code>{username}</code></p>{strip}{msg}")


@app.route("/secure/profile")
def secure_profile():
    username = request.args.get("username", "")
    query = "SELECT id FROM users WHERE username = ?"
    conn = get_connection()
    try:
        row = conn.execute(query, (username,)).fetchone()
        msg = ("<div class='box ok'>User exists</div>" if row
               else "<div class='box bad'>No such user</div>")
    finally:
        conn.close()
    strip = mode_strip("secure", "/secure/profile", "/profile?username=admin", "vulnerable version")
    return page("Username check (secure)",
                f"<h1 class='page'>Username availability</h1>"
                f"<p class='sub'>Checking username <code>{username}</code></p>{strip}{msg}")


# ===========================================================================
# 6. TRACK  ->  stacked queries
# ===========================================================================

@app.route("/track")
def track():
    pid = request.args.get("id", "1")
    script = f"UPDATE products SET views = views + 1 WHERE id = {pid};"
    conn = get_connection()
    try:
        conn.executescript(script)
        conn.commit()
        msg = "<div class='box ok'>View counted</div>"
    except sqlite3.Error as e:
        msg = f"<div class='box bad'>SQL error: {e}</div>"
    finally:
        conn.close()
    return page("Track view",
                f"<h1 class='page'>Track product view</h1>{msg}"
                f"<div class='querylabel'>Script that ran</div><pre>{script}</pre>")


@app.route("/secure/track")
def secure_track():
    pid = request.args.get("id", "1")
    if not pid.isdigit():
        return page("Track view (secure)",
                    "<h1 class='page'>Track product view</h1>"
                    "<div class='box bad'>Invalid product id</div>")
    conn = get_connection()
    try:
        conn.execute("UPDATE products SET views = views + 1 WHERE id = ?", (int(pid),))
        conn.commit()
        msg = "<div class='box ok'>View counted</div>"
    finally:
        conn.close()
    return page("Track view (secure)",
                f"<h1 class='page'>Track product view</h1>{msg}")


# ===========================================================================
# 7. SECOND ORDER (register stores safely, reset trusts the stored value)
# ===========================================================================

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = get_connection()
    try:
        conn.execute("INSERT INTO users (username, password, role) "
                     "VALUES (?, ?, 'user')", (username, password))
        conn.commit()
        msg = f"Registered username: {username}"
    except sqlite3.Error as e:
        msg = f"error: {e}"
    finally:
        conn.close()
    return jsonify({"message": msg})


@app.route("/reset", methods=["POST"])
def reset():
    acting_user_id = request.form.get("user_id", "")
    new_password = request.form.get("new_password", "")
    conn = get_connection()
    try:
        stored = conn.execute("SELECT username FROM users WHERE id = ?",
                              (acting_user_id,)).fetchone()
        if not stored:
            return jsonify({"message": "no such account"})
        stored_username = stored["username"]
        # VULNERABLE: the stored username is trusted and concatenated.
        update = (f"UPDATE users SET password = '{new_password}' "
                  f"WHERE username = '{stored_username}'")
        conn.executescript(update)
        conn.commit()
        return jsonify({"message": "password reset ran", "query": update})
    except sqlite3.Error as e:
        return jsonify({"message": f"error: {e}"})
    finally:
        conn.close()


@app.route("/debug/users")
def debug_users():
    conn = get_connection()
    rows = conn.execute("SELECT id, username, password, role FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
