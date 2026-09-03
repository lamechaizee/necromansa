import { Router } from 'express';
import bcrypt from 'bcryptjs';
import db from '../db.js';
import { authMiddleware, generateToken } from '../auth.js';

const router = Router();

// Register
router.post('/register', (req, res) => {
  const { username, displayName, password, publicSignKey, publicEncKey } = req.body;

  if (!username || !displayName || !password || !publicSignKey || !publicEncKey) {
    return res.status(400).json({ error: 'All fields required' });
  }

  if (username.length < 3 || username.length > 20) {
    return res.status(400).json({ error: 'Username must be 3-20 characters' });
  }

  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return res.status(400).json({ error: 'Username: letters, numbers, underscore only' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(409).json({ error: 'Username taken' });
  }

  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (userCount.count >= 10) {
    return res.status(403).json({ error: 'Maximum 10 users reached' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);

  const result = db.prepare(
    'INSERT INTO users (username, display_name, bio, public_sign_key, public_enc_key, password_hash) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(username, displayName, '', publicSignKey, publicEncKey, passwordHash);

  const token = generateToken(result.lastInsertRowid);

  res.json({
    token,
    user: {
      id: result.lastInsertRowid,
      username,
      displayName,
      bio: '',
      publicSignKey,
      publicEncKey
    }
  });
});

// Login
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  db.prepare('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

  const token = generateToken(user.id);

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      displayName: user.display_name,
      bio: user.bio,
      publicSignKey: user.public_sign_key,
      publicEncKey: user.public_enc_key
    }
  });
});

// Search users
router.get('/search', authMiddleware, (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 1) {
    return res.json([]);
  }

  const users = db.prepare(
    `SELECT id, username, display_name, bio, public_sign_key, public_enc_key, last_seen
     FROM users WHERE username LIKE ? OR display_name LIKE ? LIMIT 20`
  ).all(`%${q}%`, `%${q}%`);

  res.json(users.map(u => ({
    id: u.id,
    username: u.username,
    displayName: u.display_name,
    bio: u.bio,
    publicSignKey: u.public_sign_key,
    publicEncKey: u.public_enc_key,
    lastSeen: u.last_seen
  })));
});

// Get user profile
router.get('/:id', authMiddleware, (req, res) => {
  const user = db.prepare(
    'SELECT id, username, display_name, bio, public_sign_key, public_enc_key, last_seen FROM users WHERE id = ?'
  ).get(req.params.id);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    bio: user.bio,
    publicSignKey: user.public_sign_key,
    publicEncKey: user.public_enc_key,
    lastSeen: user.last_seen
  });
});

// Update profile
router.put('/profile', authMiddleware, (req, res) => {
  const { displayName, bio } = req.body;

  if (displayName !== undefined) {
    db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(displayName, req.userId);
  }
  if (bio !== undefined) {
    db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(bio, req.userId);
  }

  const user = db.prepare('SELECT id, username, display_name, bio FROM users WHERE id = ?').get(req.userId);

  res.json({
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    bio: user.bio
  });
});

export default router;
