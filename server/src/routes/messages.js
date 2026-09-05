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
    SELECT id, sender_id, recipient_id, ciphertext, nonce, ephemeral_pub, signature, created_at, delivered, delivered_at, read, read_at
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
    'UPDATE messages SET delivered = 1, delivered_at = CURRENT_TIMESTAMP WHERE sender_id = ? AND recipient_id = ? AND delivered = 0'
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
    deliveredAt: m.delivered_at,
    read: !!m.read,
    readAt: m.read_at
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

// Delete a message (unsend)
router.delete('/:messageId', authMiddleware, (req, res) => {
  const messageId = parseInt(req.params.messageId);

  const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(messageId);
  if (!message) {
    return res.status(404).json({ error: 'Message not found' });
  }

  if (message.sender_id !== req.userId) {
    return res.status(403).json({ error: 'Can only delete your own messages' });
  }

  db.prepare('DELETE FROM messages WHERE id = ?').run(messageId);

  res.json({ ok: true, recipientId: message.recipient_id });
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
