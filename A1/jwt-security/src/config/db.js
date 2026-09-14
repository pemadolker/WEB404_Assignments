const Database = require('better-sqlite3');
const path = require('path');

// Single local SQLite file. Chosen so the database itself introduces
// no separate attack surface (no network listener, no auth of its own)
// — it keeps the assignment's focus on the JWT/auth layer, not DB hardening.
const dbPath = path.join(__dirname, '..', '..', 'jwt_lab.sqlite');
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

// Schema: password_hash only — never store plaintext passwords.
// role is a plain column; the SECURE authorization middleware will
// re-read this column from the DB rather than trusting a JWT claim
// for high-privilege actions. This is the load-bearing design decision
// for the privilege-escalation demonstration later.
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )
`);

module.exports = db;