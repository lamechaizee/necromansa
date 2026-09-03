import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import usersRouter from './routes/users.js';
import messagesRouter from './routes/messages.js';
import { verifyToken } from './auth.js';
import db from './db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const server = createServer(app);

const PORT = process.env.PORT || 3000;
const ORIGIN = process.env.ORIGIN || '*';

app.use(cors({ origin: ORIGIN }));
app.use(express.json({ limit: '10mb' }));

// Serve static files from necromansa root
app.use(express.static(join(__dirname, '..', '..', '..')));

// API routes
app.use('/api/users', usersRouter);
app.use('/api/messages', messagesRouter);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Socket.IO
const io = new Server(server, {
  cors: { origin: ORIGIN, methods: ['GET', 'POST'] }
});

// Track online users: userId -> Set of socket IDs
const onlineUsers = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication required'));

  const decoded = verifyToken(token);
  if (!decoded) return next(new Error('Invalid token'));

  socket.userId = decoded.userId;
  next();
});

io.on('connection', (socket) => {
  const userId = socket.userId;

  // Add to online users
  if (!onlineUsers.has(userId)) {
    onlineUsers.set(userId, new Set());
  }
  onlineUsers.get(userId).add(socket.id);

  // Update last seen
  db.prepare('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?').run(userId);

  // Broadcast online status
  io.emit('user_online', { userId, online: true });

  console.log(`User ${userId} connected (${socket.id})`);

  // Handle sending messages
  socket.on('send_message', (data) => {
    const { recipientId, ciphertext, nonce, ephemeralPub, signature } = data;

    if (!recipientId || !ciphertext || !nonce || !ephemeralPub || !signature) {
      return socket.emit('error', { message: 'Invalid message format' });
    }

    // Store message
    const result = db.prepare(
      `INSERT INTO messages (sender_id, recipient_id, ciphertext, nonce, ephemeral_pub, signature)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(userId, recipientId, ciphertext, nonce, ephemeralPub, signature);

    const message = {
      id: result.lastInsertRowid,
      senderId: userId,
      recipientId,
      ciphertext,
      nonce,
      ephemeralPub,
      signature,
      createdAt: new Date().toISOString(),
      delivered: false,
      read: false
    };

    // Send to recipient if online
    const recipientSockets = onlineUsers.get(recipientId);
    if (recipientSockets) {
      for (const sid of recipientSockets) {
        io.to(sid).emit('message', message);
      }
      // Mark as delivered
      db.prepare('UPDATE messages SET delivered = 1 WHERE id = ?').run(message.id);
      message.delivered = true;
    }

    // Confirm to sender
    socket.emit('message_sent', { ...message, tempId: data.tempId });
  });

  // Typing indicator
  socket.on('typing', ({ recipientId }) => {
    const recipientSockets = onlineUsers.get(recipientId);
    if (recipientSockets) {
      for (const sid of recipientSockets) {
        io.to(sid).emit('typing', { userId });
      }
    }
  });

  // Stop typing
  socket.on('stop_typing', ({ recipientId }) => {
    const recipientSockets = onlineUsers.get(recipientId);
    if (recipientSockets) {
      for (const sid of recipientSockets) {
        io.to(sid).emit('stop_typing', { userId });
      }
    }
  });

  // Mark as read
  socket.on('mark_read', ({ senderId }) => {
    db.prepare(
      'UPDATE messages SET read = 1 WHERE sender_id = ? AND recipient_id = ? AND read = 0'
    ).run(senderId, userId);

    const senderSockets = onlineUsers.get(senderId);
    if (senderSockets) {
      for (const sid of senderSockets) {
        io.to(sid).emit('messages_read', { byUserId: userId });
      }
    }
  });

  // Disconnect
  socket.on('disconnect', () => {
    const sockets = onlineUsers.get(userId);
    if (sockets) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        onlineUsers.delete(userId);
        db.prepare('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?').run(userId);
        io.emit('user_online', { userId, online: false });
      }
    }
    console.log(`User ${userId} disconnected (${socket.id})`);
  });
});

server.listen(PORT, () => {
  console.log(`NECROMANSA server running on port ${PORT}`);
});
