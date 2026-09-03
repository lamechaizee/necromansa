import { Router } from 'express';
import db from '../db.js';
import { authMiddleware } from '../auth.js';

const router = Router();

// Get message history with a user
router.get('/:userId', authMiddleware, (req, res) => {
  const otherId = parseInt(req.params.userId);
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const before = req.query.before ? parseInt(req.query.before) : null;

  let query = `
    SELECT id, sender_id, recipient_id, ciphertext, nonce, ephemeral_pub, signature, created_at, delivered, read
    FROM messages
    WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
  `;
  const params = [req.userId, otherId, otherId, req.userId];

  if (before) {
    query += ' AND id < ?';
    params.push(before);
  }

  query += ' ORDER BY created_at DESC LIMIT ?';
  params.push(limit);

  const messages = db.prepare(query).all(...params);

  // Mark messages from other user as delivered
  db.prepare(
    'UPDATE messages SET delivered = 1 WHERE sender_id = ? AND recipient_id = ? AND delivered = 0'
  ).run(otherId, req.userId);

  res.json(messages.map(m => ({
    id: m.id,
    senderId: m.sender_id,
    recipientId: m.recipient_id,
    ciphertext: m.ciphertext,
    nonce: m.nonce,
    ephemeralPub: m.ephemeral_pub,
    signature: m.signature,
    createdAt: m.created_at,
    delivered: !!m.delivered,
    read: !!m.read
  })).reverse());
});

// Mark messages as read
router.post('/:userId/read', authMiddleware, (req, res) => {
  const otherId = parseInt(req.params.userId);

  db.prepare(
    'UPDATE messages SET read = 1 WHERE sender_id = ? AND recipient_id = ? AND read = 0'
  ).run(otherId, req.userId);

  res.json({ ok: true });
});

// Get unread counts
router.get('/unread/counts', authMiddleware, (req, res) => {
  const counts = db.prepare(
    `SELECT sender_id, COUNT(*) as count
     FROM messages WHERE recipient_id = ? AND read = 0
     GROUP BY sender_id`
  ).all(req.userId);

  const result = {};
  for (const row of counts) {
    result[row.sender_id] = row.count;
  }

  res.json(result);
});

export default router;
