const db = require('../config/db');

const User = {
  create(username, passwordHash, role = 'user') {
    const stmt = db.prepare(
      'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)'
    );
    const info = stmt.run(username, passwordHash, role);
    return { id: info.lastInsertRowid, username, role };
  },

  findByUsername(username) {
    return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  },

  findById(id) {
    return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  },

  all() {
    // Never select password_hash for a general listing endpoint.
    return db.prepare('SELECT id, username, role, created_at FROM users').all();
  }
};

module.exports = User;