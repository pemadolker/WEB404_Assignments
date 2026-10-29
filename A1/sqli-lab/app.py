"""
app.py  -  Norbu Electronics
An online electronics store. The store is a normal looking web app; the SQL
injection flaws are real but not advertised anywhere in the interface, exactly
as they would be on a genuine vulnerable site.

The attacks and the fixes are documented in the lab report, not on the page.

Routes:
  /                     storefront
  /product, /search     product browsing   (UNION injection points)
  /login                account sign in     (auth bypass, error based)
  /account              account / admin dashboard after login
  /check-username       registration helper (blind injection point)
  /track                view counter        (stacked queries)
  /register, /reset     (second order injection)

Each vulnerable feature has a hardened counterpart under /secure/ used by the
report to show the before and after. The secure routes render the same pages,
so they look identical; only the query handling differs.

WARNING: insecure on purpose. Run only on localhost.
"""

from flask import (Flask, request, render_template_string, redirect, url_for,
                   session, jsonify)
import sqlite3
from database import init_db, get_connection

app = Flask(__name__)
app.secret_key = "norbu-store-session"
init_db()

IMG = {"keyboard": "keyboard", "mouse": "mouse", "monitor": "monitor",
       "webcam": "webcam"}


def display_name(username):
    return " ".join(p.capitalize() for p in username.replace(".", " ").split())


# ---------------------------------------------------------------------------
# Shell
# ---------------------------------------------------------------------------

SHELL = """
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} - Norbu Electronics</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head><body>
<div class="topbar">
  <a href="/" class="brand"><span class="dot"></span>
    <div>Norbu Electronics<small>Thimphu's online tech store</small></div></a>
  <div class="searchbar">
    <form method="get" action="/search">
      <input name="q" placeholder="Search products..." value="">
      <button>Search</button>
    </form>
  </div>
  <div class="topnav">
    <a href="/">Store</a>
    {% if user %}<a href="/account">{{ display }}</a>
      <a href="/logout">Sign out</a>
    {% else %}<a href="/login">Sign in</a>{% endif %}
    <a href="/cart" class="cart">Cart</a>
  </div>
</div>
<div class="wrap">
{{ body|safe }}
</div>
<footer>&copy; 2026 Norbu Electronics Pvt. Ltd., Thimphu. All rights reserved.</footer>
</body></html>
"""


def page(title, body):
    user = session.get("user")
    return render_template_string(SHELL, title=title, body=body, user=user,
                                  display=display_name(user) if user else "")


# ---------------------------------------------------------------------------
# Storefront
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
            <img src="{url_for('static', filename='img/'+img+'.jpg')}" alt="{r['name']}">
          </div></a>
          <div class="body"><div class="name">{r['name']}</div>
            <div class="desc">{r['description']}</div>
            <div class="foot"><span class="price">Nu. {int(r['price']):,}</span>
              <a class="view" href="/product?id={r['id']}">View &rarr;</a></div></div>
        </div>"""
    body = f"""
    <div class="hero"><span class="tagpill">New arrivals this week</span>
      <h1>Gear up for the semester.</h1>
      <p>Keyboards, monitors and accessories, delivered across Thimphu. Sign in
      to track orders and save your cart.</p></div>
    <div class="sectionhead"><h2>Popular products</h2>
      <span class="muted">{len(rows)} items</span></div>
    <div class="grid">{cards}</div>
    """
    return page("Store", body)


@app.route("/cart")
def cart():
    return page("Cart", "<h1 class='page'>Your cart</h1>"
                "<div class='box'>Your cart is empty.</div>")


# ---------------------------------------------------------------------------
# Product browsing  (UNION injection points, numeric and string)
# ---------------------------------------------------------------------------

def results_table(rows):
    if not rows:
        return "<div class='box'>No products found.</div>"
    body = ""
    for r in rows:
        cells = "".join(f"<td>{r[i]}</td>" for i in range(len(r)))
        body += f"<tr>{cells}</tr>"
    return ("<table><tr><th>#</th><th>Product</th><th>Description</th>"
            f"<th>Price</th></tr>{body}</table>")


@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    query = f"SELECT id, name, description, price FROM products WHERE id = {pid}"
    conn = get_connection()
    try:
        rows = conn.execute(query).fetchall()
        out = results_table(rows)
    except sqlite3.Error as e:
        out = f"<div class='box bad'>Database error: {e}</div>"
    finally:
        conn.close()
    return page("Product", f"<h1 class='page'>Product</h1>{out}")


@app.route("/secure/product")
def secure_product():
    pid = request.args.get("id", "1")
    if not pid.isdigit():
        return page("Product", "<h1 class='page'>Product</h1>"
                    "<div class='box bad'>Product not found.</div>")
    conn = get_connection()
    rows = conn.execute("SELECT id, name, description, price FROM products "
                        "WHERE id = ?", (int(pid),)).fetchall()
    conn.close()
    return page("Product", f"<h1 class='page'>Product</h1>{results_table(rows)}")


@app.route("/search")
def search():
    term = request.args.get("q", "")
    query = ("SELECT id, name, description, price FROM products "
             f"WHERE name LIKE '%{term}%'")
    conn = get_connection()
    try:
        rows = conn.execute(query).fetchall()
        out = results_table(rows)
    except sqlite3.Error as e:
        out = f"<div class='box bad'>Database error: {e}</div>"
    finally:
        conn.close()
    return page("Search", f"<h1 class='page'>Search results</h1>"
                f"<p class='sub'>Showing results for &ldquo;{term}&rdquo;</p>{out}")


@app.route("/secure/search")
def secure_search():
    term = request.args.get("q", "")
    conn = get_connection()
    rows = conn.execute("SELECT id, name, description, price FROM products "
                        "WHERE name LIKE ?", (f"%{term}%",)).fetchall()
    conn.close()
    return page("Search", f"<h1 class='page'>Search results</h1>"
                f"<p class='sub'>Showing results for &ldquo;{term}&rdquo;</p>"
                f"{results_table(rows)}")


# ---------------------------------------------------------------------------
# Account sign in  (auth bypass + error based)
# ---------------------------------------------------------------------------

LOGIN_FORM = """
<h1 class="page">Sign in to your account</h1>
<p class="sub">Access your orders and saved items.</p>
<div class="panel narrow">
  {% if error %}<div class="box bad">{{ error }}</div>{% endif %}
  <form method="post">
    <label>Username</label>
    <input type="text" name="username" placeholder="your username">
    <label>Password</label>
    <input type="password" name="password" placeholder="your password">
    <button class="btn">Sign in</button>
  </form>
</div>
"""


def login_core(secure):
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = get_connection()
    try:
        if secure:
            row = conn.execute("SELECT id, username, role FROM users "
                               "WHERE username = ? AND password = ?",
                               (username, password)).fetchone()
        else:
            q = ("SELECT id, username, role FROM users "
                 f"WHERE username = '{username}' AND password = '{password}'")
            row = conn.execute(q).fetchone()
    except sqlite3.Error as e:
        conn.close()
        # vulnerable path leaks the error; secure path hides it
        if secure:
            return render_template_string(LOGIN_FORM, error="Something went wrong.")
        return render_template_string(LOGIN_FORM, error=f"Database error: {e}")
    conn.close()
    if row:
        session["user"] = row["username"]
        session["role"] = row["role"]
        return None  # signal: redirect to account
    return render_template_string(LOGIN_FORM, error="Incorrect username or password.")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        res = login_core(secure=False)
        if res is None:
            return redirect(url_for("account"))
        return page("Sign in", res)
    return page("Sign in", render_template_string(LOGIN_FORM, error=""))


@app.route("/secure/login", methods=["GET", "POST"])
def secure_login():
    if request.method == "POST":
        res = login_core(secure=True)
        if res is None:
            return redirect(url_for("account"))
        return page("Sign in", res)
    return page("Sign in", render_template_string(LOGIN_FORM, error=""))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/account")
def account():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    name = display_name(user)
    conn = get_connection()
    if session.get("role") == "admin":
        users = conn.execute("SELECT username, email, role FROM users").fetchall()
        orders = conn.execute("SELECT customer, item, total FROM orders").fetchall()
        conn.close()
        urows = "".join(f"<tr><td>{u['username']}</td><td>{u['email']}</td>"
                        f"<td>{u['role']}</td></tr>" for u in users)
        orows = "".join(f"<tr><td>{o['customer']}</td><td>{o['item']}</td>"
                        f"<td>Nu. {int(o['total']):,}</td></tr>" for o in orders)
        body = f"""
        <h1 class="page">Admin dashboard</h1>
        <p class="sub">Signed in as {name} &middot; administrator</p>
        <div class="panel"><h2 class="ph2">All customer accounts</h2>
          <table><tr><th>Username</th><th>Email</th><th>Role</th></tr>{urows}</table></div>
        <div class="panel"><h2 class="ph2">Recent orders</h2>
          <table><tr><th>Customer</th><th>Item</th><th>Total</th></tr>{orows}</table></div>
        """
    else:
        orders = conn.execute("SELECT item, total FROM orders WHERE customer = ?",
                              (name,)).fetchall()
        conn.close()
        orows = ("".join(f"<tr><td>{o['item']}</td><td>Nu. {int(o['total']):,}</td></tr>"
                         for o in orders)
                 or "<tr><td colspan=2>No orders yet.</td></tr>")
        body = f"""
        <h1 class="page">Welcome back, {name}</h1>
        <p class="sub">Your account overview.</p>
        <div class="panel"><h2 class="ph2">Your orders</h2>
          <table><tr><th>Item</th><th>Total</th></tr>{orows}</table></div>
        """
    return page("My account", body)


# ---------------------------------------------------------------------------
# Registration username check  (blind: boolean + time based)
# ---------------------------------------------------------------------------

@app.route("/check-username")
def check_username():
    username = request.args.get("username", "")
    query = f"SELECT id FROM users WHERE username = '{username}'"
    conn = get_connection()
    try:
        row = conn.execute(query).fetchone()
        msg = ("<div class='box bad'>That username is already taken.</div>" if row
               else "<div class='box ok'>That username is available.</div>")
    except sqlite3.Error:
        msg = "<div class='box ok'>That username is available.</div>"
    finally:
        conn.close()
    return page("Username check", f"<h1 class='page'>Choose a username</h1>"
                f"<p class='sub'>Checking &ldquo;{username}&rdquo;</p>{msg}")


@app.route("/secure/check-username")
def secure_check_username():
    username = request.args.get("username", "")
    conn = get_connection()
    row = conn.execute("SELECT id FROM users WHERE username = ?",
                       (username,)).fetchone()
    conn.close()
    msg = ("<div class='box bad'>That username is already taken.</div>" if row
           else "<div class='box ok'>That username is available.</div>")
    return page("Username check", f"<h1 class='page'>Choose a username</h1>"
                f"<p class='sub'>Checking &ldquo;{username}&rdquo;</p>{msg}")


# ---------------------------------------------------------------------------
# View counter  (stacked queries)
# ---------------------------------------------------------------------------

@app.route("/track")
def track():
    pid = request.args.get("id", "1")
    script = f"UPDATE products SET views = views + 1 WHERE id = {pid};"
    conn = get_connection()
    try:
        conn.executescript(script)
        conn.commit()
        msg = "<div class='box ok'>Thanks, your view was recorded.</div>"
    except sqlite3.Error as e:
        msg = f"<div class='box bad'>Error: {e}</div>"
    finally:
        conn.close()
    return page("Track", f"<h1 class='page'>Product view</h1>{msg}")


@app.route("/secure/track")
def secure_track():
    pid = request.args.get("id", "1")
    if not pid.isdigit():
        return page("Track", "<h1 class='page'>Product view</h1>"
                    "<div class='box bad'>Invalid request.</div>")
    conn = get_connection()
    conn.execute("UPDATE products SET views = views + 1 WHERE id = ?", (int(pid),))
    conn.commit()
    conn.close()
    return page("Track", "<h1 class='page'>Product view</h1>"
                "<div class='box ok'>Thanks, your view was recorded.</div>")


# ---------------------------------------------------------------------------
# Second order (register stores safely, reset trusts the stored value)
# ---------------------------------------------------------------------------

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
