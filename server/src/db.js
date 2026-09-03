import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DB_PATH = join(__dirname, '..', 'necromansa.db');

const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    bio TEXT DEFAULT '',
    public_sign_key TEXT NOT NULL,
    public_enc_key TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    ciphertext TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ephemeral_pub TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    delivered INTEGER DEFAULT 0,
    read INTEGER DEFAULT 0,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (recipient_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
  CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
  CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
  CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
`);

export default db;
