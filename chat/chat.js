// NECROMANSA Chat Module
// Socket.IO connection, message handling, chat state

import { encryptMessage, decryptMessage, encryptBlob, decryptBlob } from './crypto.js';
import { getAuthToken, getCurrentUserId, getMessages, markMessagesRead, getUnreadCounts } from './contacts.js';

let socket = null;
let messageHandlers = new Map();
let typingTimers = new Map();
let reconnectAttempts = 0;
const MAX_RECONNECT = 10;

// Offline message queue
let offlineQueue = [];
let wasConnected = false;

// User's keys (set after login)
let userKeys = {
  signPrivateKey: null,
  encPrivateKey: null,
  signPublicKey: null,
  encPublicKey: null
};

// Cache of other users' public keys
let publicKeyCache = new Map();

export function setUserKeys(keys) {
  userKeys = keys;
}

export function cachePublicKey(userId, keys) {
  publicKeyCache.set(userId, keys);
}

export function getCachedPublicKey(userId) {
  return publicKeyCache.get(userId);
}

// Connect to Socket.IO server
export function connectSocket(serverUrl) {
  const token = getAuthToken();
  if (!token) throw new Error('Not authenticated');

  socket = io(serverUrl, {
    auth: { token },
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    reconnectionAttempts: MAX_RECONNECT
  });

  socket.on('connect', () => {
    console.log('Socket connected');
    reconnectAttempts = 0;
    emit('connection_status', { connected: true });

    // Flush offline queue
    if (offlineQueue.length > 0) {
      const queue = [...offlineQueue];
      offlineQueue = [];
      for (const item of queue) {
        socket.emit(item.event, item.data);
      }
    }
    wasConnected = true;
  });

  socket.on('disconnect', (reason) => {
    console.log('Socket disconnected:', reason);
    emit('connection_status', { connected: false, reason });
  });

  socket.on('connect_error', (err) => {
    console.error('Socket connection error:', err.message);
    reconnectAttempts++;
    emit('connection_status', { connected: false, error: err.message });
  });

  socket.on('message', async (message) => {
    try {
      const decrypted = await decryptIncoming(message);
      emit('new_message', decrypted);
    } catch (err) {
      console.error('Failed to decrypt incoming message:', err);
      emit('decrypt_error', { messageId: message.id, error: err.message });
    }
  });

  socket.on('message_sent', async (message) => {
    try {
      const decrypted = await decryptIncoming(message);
      emit('message_confirmed', { ...decrypted, tempId: message.tempId });
    } catch (err) {
      emit('message_confirmed', { id: message.id, tempId: message.tempId, error: err.message });
    }
  });

  socket.on('typing', ({ userId }) => {
    emit('typing', { userId });
  });

  socket.on('stop_typing', ({ userId }) => {
    emit('stop_typing', { userId });
  });

  socket.on('messages_read', ({ byUserId, at }) => {
    emit('messages_read', { byUserId, at });
  });

  socket.on('user_online', ({ userId, online }) => {
    emit('user_online', { userId, online });
  });

  socket.on('message_deleted', ({ messageId, byUserId }) => {
    emit('message_deleted', { messageId, byUserId });
  });

  return socket;
}

export function disconnectSocket() {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
}

export function isConnected() {
  return socket && socket.connected;
}

// Decrypt an incoming message
async function decryptIncoming(message) {
  const senderKeys = publicKeyCache.get(message.senderId);
  if (!senderKeys) {
    throw new Error(`No public keys cached for user ${message.senderId}`);
  }

  const plaintext = decryptMessage(
    {
      ciphertext: message.ciphertext,
      nonce: message.nonce,
      ephemeralPub: message.ephemeralPub,
      signature: message.signature
    },
    senderKeys.signPublicKey,
    userKeys.encPrivateKey
  );

  return {
    ...message,
    plaintext,
    isOwn: message.senderId === getCurrentUserId()
  };
}

// Send a text message
export async function sendMessage(recipientId, text) {
  const recipientKeys = publicKeyCache.get(recipientId);
  if (!recipientKeys) {
    throw new Error(`No public keys cached for user ${recipientId}`);
  }

  const encrypted = encryptMessage(
    text,
    recipientKeys.encPublicKey,
    userKeys.signPrivateKey
  );

  const tempId = 'temp_' + Date.now() + '_' + Math.random().toString(36).slice(2);

  const payload = { recipientId, ...encrypted, tempId };

  if (socket && socket.connected) {
    socket.emit('send_message', payload);
  } else {
    offlineQueue.push({ event: 'send_message', data: payload });
  }

  return tempId;
}

// Delete a message (unsend)
export function deleteMessage(messageId) {
  if (socket && socket.connected) {
    socket.emit('delete_message', { messageId });
  }
}

// Send an image message
export async function sendImageMessage(recipientId, file) {
  const recipientKeys = publicKeyCache.get(recipientId);
  if (!recipientKeys) {
    throw new Error(`No public keys cached for user ${recipientId}`);
  }

  const arrayBuffer = await file.arrayBuffer();
  const encrypted = encryptBlob(
    arrayBuffer,
    recipientKeys.encPublicKey,
    userKeys.signPrivateKey
  );

  const imagePayload = JSON.stringify({
    type: 'image',
    filename: file.name,
    mimeType: file.type,
    size: file.size,
    ...encrypted
  });

  const encMessage = encryptMessage(
    imagePayload,
    recipientKeys.encPublicKey,
    userKeys.signPrivateKey
  );

  const tempId = 'temp_' + Date.now() + '_' + Math.random().toString(36).slice(2);

  socket.emit('send_message', {
    recipientId,
    ...encMessage,
    tempId
  });

  return tempId;
}

// Load message history and decrypt
export async function loadMessages(userId) {
  const messages = await getMessages(userId);
  const decrypted = [];

  for (const msg of messages) {
    try {
      const plain = await decryptIncoming(msg);
      decrypted.push(plain);
    } catch (err) {
      console.error(`Failed to decrypt message ${msg.id}:`, err);
      decrypted.push({
        ...msg,
        plaintext: '[Decryption failed]',
        isOwn: msg.senderId === getCurrentUserId(),
        decryptError: true
      });
    }
  }

  return decrypted;
}

// Mark messages from a user as read
export function markRead(senderId) {
  if (socket) {
    socket.emit('mark_read', { senderId });
  }
  markMessagesRead(senderId).catch(console.error);
}

// Send typing indicator
export function sendTyping(recipientId) {
  if (socket) {
    socket.emit('typing', { recipientId });
  }
}

// Send stop typing indicator
export function sendStopTyping(recipientId) {
  if (socket) {
    socket.emit('stop_typing', { recipientId });
  }
}

// Debounced typing
export function debouncedTyping(recipientId) {
  sendTyping(recipientId);

  const existing = typingTimers.get(recipientId);
  if (existing) clearTimeout(existing);

  const timer = setTimeout(() => {
    sendStopTyping(recipientId);
    typingTimers.delete(recipientId);
  }, 2000);

  typingTimers.set(recipientId, timer);
}

// Event system
function emit(event, data) {
  const handlers = messageHandlers.get(event);
  if (handlers) {
    for (const handler of handlers) {
      try { handler(data); } catch (e) { console.error(e); }
    }
  }
}

export function on(event, handler) {
  if (!messageHandlers.has(event)) {
    messageHandlers.set(event, new Set());
  }
  messageHandlers.get(event).add(handler);
  return () => messageHandlers.get(event)?.delete(handler);
}

export function off(event, handler) {
  messageHandlers.get(event)?.delete(handler);
}
