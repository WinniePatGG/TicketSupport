const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
const dbPath = path.join(dataDir, 'support.sqlite3');

const db = new sqlite3.Database(dbPath);

function initDb(callback) {
  db.serialize(() => {
    db.run('PRAGMA foreign_keys = ON');

    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password_hash TEXT,
        google_id TEXT UNIQUE,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT
      )`
    );

    db.run(
      `CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        subject TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        created_at TEXT,
        updated_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`
    );

    db.run('CREATE INDEX IF NOT EXISTS idx_tickets_user_id ON tickets(user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status)');

    db.run(
      `CREATE TABLE IF NOT EXISTS ticket_responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        is_admin_response INTEGER NOT NULL DEFAULT 0,
        created_at TEXT,
        FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`
    );

    if (typeof callback === 'function') callback();
  });
}

module.exports = { db, initDb };
