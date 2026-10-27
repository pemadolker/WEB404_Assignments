"""
database.py
Builds a small SQLite database that the lab app runs on.

The database is rebuilt from scratch every time the app starts, so any damage
done during an attack demo (changed roles, changed passwords, dropped rows) is
reset on the next run. This keeps the lab repeatable.

The data is deliberately simple. The point of the lab is the queries the app
builds around this data, not the data itself.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")


def get_connection():
    """Open a connection. Row factory lets us read columns by name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Drop everything and recreate the tables with fresh seed data."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = get_connection()
    cur = conn.cursor()

    # Users of the application. password is stored in plain text ON PURPOSE.
    # Plain text is itself a bad practice, but it makes the injection demos
    # readable: when we steal a password column we can see what we stole.
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email TEXT
        )
    """)

    cur.executemany(
        "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
        [
            ("admin", "S3cr3t_Admin!2026", "admin", "admin@shop.bt"),
            ("pema", "pema123", "user", "pema@shop.bt"),
            ("sonam", "sonam456", "user", "sonam@shop.bt"),
            ("guest", "guest", "user", "guest@shop.bt"),
        ],
    )

    # Products shown in the shop. views is used by the stacked query demo.
    cur.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            views INTEGER DEFAULT 0
        )
    """)

    cur.executemany(
        "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
        [
            ("Keyboard", "Mechanical keyboard, blue switches", 2400.0),
            ("Mouse", "Wireless optical mouse", 900.0),
            ("Monitor", "27 inch 1440p display", 18500.0),
            ("Webcam", "1080p USB webcam", 3200.0),
        ],
    )

    # A table the normal app never shows. It exists so a UNION attack has
    # something worth stealing that the UI was never meant to expose.
    cur.execute("""
        CREATE TABLE app_secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            value TEXT NOT NULL
        )
    """)

    cur.executemany(
        "INSERT INTO app_secrets (name, value) VALUES (?, ?)",
        [
            ("payment_api_key", "sk_live_8fQ2zR_do_not_leak_this"),
            ("jwt_signing_secret", "kuzuzangpo_la_super_secret"),
        ],
    )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database built at", DB_PATH)
