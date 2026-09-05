// NECROMANSA Chat UI Module
// Renders chat interface, handles user interactions

import { initCrypto, generateSigningKeypair, generateEncryptionKeypair, encryptPrivateKey, decryptPrivateKey } from './crypto.js';
import { register, login, searchUsers, getUserProfile, updateProfile, saveChatSession, loadChatSession, clearChatSession, setAuth, getCurrentUserId, getUnreadCounts } from './contacts.js';
import { connectSocket, disconnectSocket, setUserKeys, cachePublicKey, getCachedPublicKey, sendMessage, sendImageMessage, deleteMessage, loadMessages, markRead, debouncedTyping, on, off, isConnected } from './chat.js';

let currentChatUser = null;
let chatMessages = [];
let onlineUsers = new Set();
let unreadCounts = {};
let contactsCache = [];
let isTyping = false;
let typingTimeout = null;

// Initialize chat system
export async function initChat() {
  await initCrypto();

  // Check for existing session
  const session = loadChatSession();
  if (session && session.token) {
    try {
      setAuth(session.token, session.userId);
      setUserKeys({
        signPrivateKey: session.signPrivateKey,
        encPrivateKey: session.encPrivateKey,
        signPublicKey: session.signPublicKey,
        encPublicKey: session.encPublicKey
      });
      await connectAndSetup(session.serverUrl || window.NECROMANSA_API || '');
      return true;
    } catch (err) {
      console.error('Session restore failed:', err);
      clearChatSession();
    }
  }
  return false;
}

// Show chat login/register UI
export function showAuthScreen() {
  const container = document.getElementById('chat-auth');
  if (!container) return;

  container.innerHTML = `
    <div class="chat-auth-container">
      <div class="chat-auth-header">
        <h2 class="chat-auth-title">SECURE MESSENGER</h2>
        <p class="chat-auth-subtitle">E2E Encrypted // Max 10 Users</p>
      </div>

      <div class="chat-auth-tabs">
        <button class="chat-auth-tab active" data-tab="login">LOGIN</button>
        <button class="chat-auth-tab" data-tab="register">REGISTER</button>
      </div>

      <div id="auth-login" class="chat-auth-form active">
        <div class="input-group">
          <span class="input-prefix">user:</span>
          <input type="text" id="chat-login-username" class="input-field" placeholder="username">
        </div>
        <div class="input-group">
          <span class="input-prefix">pass:</span>
          <input type="password" id="chat-login-password" class="input-field" placeholder="password">
        </div>
        <div class="input-group">
          <span class="input-prefix">vault:</span>
          <input type="password" id="chat-login-pin" class="pin-input" maxlength="6" placeholder="VAULT_PIN" inputmode="numeric" pattern="[0-9]*">
        </div>
        <button id="btn-chat-login" class="btn-primary">[ AUTHENTICATE ]</button>
        <p id="chat-login-error" class="error-text"></p>
      </div>

      <div id="auth-register" class="chat-auth-form">
        <div class="input-group">
          <span class="input-prefix">user:</span>
          <input type="text" id="chat-reg-username" class="input-field" placeholder="username (3-20 chars)">
        </div>
        <div class="input-group">
          <span class="input-prefix">name:</span>
          <input type="text" id="chat-reg-display" class="input-field" placeholder="display name">
        </div>
        <div class="input-group">
          <span class="input-prefix">pass:</span>
          <input type="password" id="chat-reg-password" class="input-field" placeholder="password">
        </div>
        <div class="input-group">
          <span class="input-prefix">vault:</span>
          <input type="password" id="chat-reg-pin" class="pin-input" maxlength="6" placeholder="VAULT_PIN (4-6 digits)" inputmode="numeric" pattern="[0-9]*">
        </div>
        <button id="btn-chat-register" class="btn-primary">[ INITIALIZE IDENTITY ]</button>
        <p id="chat-reg-error" class="error-text"></p>
      </div>

      <div class="chat-auth-footer">
        <span class="cyber-line"></span>
        <span class="footer-text">X25519 // XChaCha20-Poly1305 // Ed25519</span>
        <span class="cyber-line"></span>
      </div>
    </div>
  `;

  // Tab switching
  container.querySelectorAll('.chat-auth-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      container.querySelectorAll('.chat-auth-tab').forEach(t => t.classList.remove('active'));
      container.querySelectorAll('.chat-auth-form').forEach(f => f.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`auth-${tab.dataset.tab}`).classList.add('active');
    });
  });

  // Login handler
  document.getElementById('btn-chat-login').addEventListener('click', handleLogin);
  document.getElementById('chat-login-password').addEventListener('keydown', e => {
    if (e.key === 'Enter') handleLogin();
  });

  // Register handler
  document.getElementById('btn-chat-register').addEventListener('click', handleRegister);
  document.getElementById('chat-reg-pin').addEventListener('keydown', e => {
    if (e.key === 'Enter') handleRegister();
  });
}

async function handleLogin() {
  const username = document.getElementById('chat-login-username').value.trim();
  const password = document.getElementById('chat-login-password').value;
  const pin = document.getElementById('chat-login-pin').value;
  const errorEl = document.getElementById('chat-login-error');

  if (!username || !password || !pin) {
    errorEl.textContent = 'All fields required';
    return;
  }

  errorEl.textContent = '';

  try {
    const btn = document.getElementById('btn-chat-login');
    btn.disabled = true;
    btn.textContent = '[ AUTHENTICATING... ]';

    const data = await login(username, password);

    // Decrypt private keys from localStorage (stored during registration)
    const storedKeys = localStorage.getItem(`necromansa_keys_${username}`);
    if (!storedKeys) {
      throw new Error('No keys found for this user. Register on this device first.');
    }

    const encryptedKeys = JSON.parse(storedKeys);
    const signPrivKey = await decryptPrivateKey(encryptedKeys.signPrivate, pin);
    const encPrivKey = await decryptPrivateKey(encryptedKeys.encPrivate, pin);

    setUserKeys({
      signPrivateKey: signPrivKey,
      encPrivateKey: encPrivKey,
      signPublicKey: data.user.publicSignKey,
      encPublicKey: data.user.publicEncKey
    });

    cachePublicKey(data.user.id, {
      signPublicKey: data.user.publicSignKey,
      encPublicKey: data.user.publicEncKey
    });

    const serverUrl = window.NECROMANSA_API || '';

    saveChatSession({
      token: data.token,
      userId: data.user.id,
      username: data.user.username,
      signPrivateKey: signPrivKey,
      encPrivateKey: encPrivKey,
      signPublicKey: data.user.publicSignKey,
      encPublicKey: data.user.publicEncKey,
      serverUrl
    });

    await connectAndSetup(serverUrl);
  } catch (err) {
    errorEl.textContent = err.message;
    const btn = document.getElementById('btn-chat-login');
    btn.disabled = false;
    btn.textContent = '[ AUTHENTICATE ]';
  }
}

async function handleRegister() {
  const username = document.getElementById('chat-reg-username').value.trim();
  const displayName = document.getElementById('chat-reg-display').value.trim();
  const password = document.getElementById('chat-reg-password').value;
  const pin = document.getElementById('chat-reg-pin').value;
  const errorEl = document.getElementById('chat-reg-error');

  if (!username || !displayName || !password || !pin) {
    errorEl.textContent = 'All fields required';
    return;
  }

  if (pin.length < 4) {
    errorEl.textContent = 'Vault PIN must be 4-6 digits';
    return;
  }

  errorEl.textContent = '';

  try {
    const btn = document.getElementById('btn-chat-register');
    btn.disabled = true;
    btn.textContent = '[ GENERATING KEYS... ]';

    // Generate keypairs
    const signKp = generateSigningKeypair();
    const encKp = generateEncryptionKeypair();

    // Encrypt private keys with PIN
    const encSignPriv = await encryptPrivateKey(signKp.privateKey, pin);
    const encEncPriv = await encryptPrivateKey(encKp.privateKey, pin);

    // Register on server
    const data = await register(username, displayName, password, signKp.publicKey, encKp.publicKey);

    // Store encrypted private keys locally
    localStorage.setItem(`necromansa_keys_${username}`, JSON.stringify({
      signPrivate: encSignPriv,
      encPrivate: encEncPriv
    }));

    setUserKeys({
      signPrivateKey: signKp.privateKey,
      encPrivateKey: encKp.privateKey,
      signPublicKey: signKp.publicKey,
      encPublicKey: encKp.publicKey
    });

    cachePublicKey(data.user.id, {
      signPublicKey: signKp.publicKey,
      encPublicKey: encKp.publicKey
    });

    const serverUrl = window.NECROMANSA_API || '';

    saveChatSession({
      token: data.token,
      userId: data.user.id,
      username: data.user.username,
      signPrivateKey: signKp.privateKey,
      encPrivateKey: encKp.privateKey,
      signPublicKey: signKp.publicKey,
      encPublicKey: encKp.publicKey,
      serverUrl
    });

    await connectAndSetup(serverUrl);
  } catch (err) {
    errorEl.textContent = err.message;
    const btn = document.getElementById('btn-chat-register');
    btn.disabled = false;
    btn.textContent = '[ INITIALIZE IDENTITY ]';
  }
}

async function connectAndSetup(serverUrl) {
  connectSocket(serverUrl);
  setupSocketListeners();
  await loadUnread();
  showChatUI();

  // Wire up logout button
  const logoutBtn = document.getElementById('btn-chat-logout');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', logoutChat);
  }

  // Wire up My Profile button
  const myProfileBtn = document.getElementById('btn-my-profile');
  if (myProfileBtn) {
    myProfileBtn.addEventListener('click', async () => {
      const session = loadChatSession();
      if (session) {
        try {
          const profile = await getUserProfile(session.userId);
          showUserProfile({
            id: session.userId,
            displayName: profile.displayName,
            username: profile.username,
            bio: profile.bio,
            publicSignKey: profile.publicSignKey,
            publicEncKey: profile.publicEncKey
          });
        } catch {
          showUserProfile({
            id: session.userId,
            displayName: session.displayName || 'Me',
            username: '',
            bio: '',
            publicSignKey: session.signPublicKey || '',
            publicEncKey: session.encPublicKey || ''
          });
        }
      }
    });
  }
}

function setupSocketListeners() {
  on('new_message', (msg) => {
    if (currentChatUser && (msg.senderId === currentChatUser.id || msg.recipientId === currentChatUser.id)) {
      chatMessages.push(msg);
      appendMessage(msg);
      if (!msg.isOwn) {
        markRead(msg.senderId);
      }
    } else if (!msg.isOwn) {
      unreadCounts[msg.senderId] = (unreadCounts[msg.senderId] || 0) + 1;
      renderContactsList();
      showNotification(msg);
    }
  });

  on('message_confirmed', (msg) => {
    // Update temp message with confirmed one
    const tempEl = document.querySelector(`[data-temp-id="${msg.tempId}"]`);
    if (tempEl) {
      tempEl.dataset.messageId = msg.id;
      tempEl.classList.remove('sending');
      tempEl.classList.add('sent');
      const statusEl = tempEl.querySelector('.msg-status');
      if (statusEl) {
        if (msg.delivered) {
          statusEl.innerHTML = '<span class="receipt delivered"><span class="check">&#10003;</span><span class="check">&#10003;</span></span>';
        } else {
          statusEl.innerHTML = '<span class="receipt sent"><span class="check">&#10003;</span></span>';
        }
      }
    }
  });

  on('typing', ({ userId }) => {
    if (currentChatUser && userId === currentChatUser.id) {
      showTypingIndicator();
    }
  });

  on('stop_typing', ({ userId }) => {
    if (currentChatUser && userId === currentChatUser.id) {
      hideTypingIndicator();
    }
  });

  on('user_online', ({ userId, online }) => {
    if (online) {
      onlineUsers.add(userId);
    } else {
      onlineUsers.delete(userId);
    }
    renderContactsList();
    if (currentChatUser && currentChatUser.id === userId) {
      updateChatHeader();
    }
  });

  on('messages_read', ({ byUserId }) => {
    if (currentChatUser && currentChatUser.id === byUserId) {
      document.querySelectorAll('.message.own .msg-status').forEach(el => {
        const receipt = el.querySelector('.receipt');
        if (receipt) {
          receipt.className = 'receipt read';
        }
      });
    }
  });

  on('message_deleted', ({ messageId }) => {
    // Remove from local messages array
    chatMessages = chatMessages.filter(m => m.id !== messageId);
    // Remove from DOM
    const el = document.querySelector(`[data-message-id="${messageId}"]`);
    if (el) {
      el.style.animation = 'msgDelete 0.3s ease forwards';
      setTimeout(() => el.remove(), 300);
    }
  });

  on('connection_status', ({ connected }) => {
    const statusEl = document.getElementById('connection-status');
    if (statusEl) {
      statusEl.textContent = connected ? 'CONNECTED' : 'DISCONNECTED';
      statusEl.className = connected ? 'status-online' : 'status-offline';
    }
  });
}

async function loadUnread() {
  try {
    unreadCounts = await getUnreadCounts();
  } catch (err) {
    console.error('Failed to load unread counts:', err);
  }
}

function showChatUI() {
  const authEl = document.getElementById('chat-auth');
  const chatEl = document.getElementById('chat-main');
  if (authEl) authEl.classList.add('hidden');
  if (chatEl) chatEl.classList.remove('hidden');

  renderContactsList();
  loadRecentContacts();
}

export function showAuthIfNotLoggedIn() {
  const session = loadChatSession();
  if (!session) {
    showAuthScreen();
  }
}

// Render contacts/conversations list
async function renderContactsList() {
  const listEl = document.getElementById('contacts-list');
  if (!listEl) return;

  const session = loadChatSession();
  if (!session) return;

  // Get unique user IDs from unread counts and recent chats
  const recentChats = JSON.parse(localStorage.getItem('necromansa_recent_chats') || '[]');
  const allUserIds = new Set([...Object.keys(unreadCounts).map(Number), ...recentChats]);

  listEl.innerHTML = '';

  if (allUserIds.size === 0) {
    listEl.innerHTML = '<div class="empty-contacts">Search users to start chatting</div>';
    return;
  }

  for (const userId of allUserIds) {
    if (userId === getCurrentUserId()) continue;

    let userInfo = getCachedPublicKey(userId);
    if (!userInfo || !userInfo.displayName) {
      try {
        const profile = await getUserProfile(userId);
        userInfo = { ...userInfo, ...profile };
        cachePublicKey(userId, {
          signPublicKey: profile.publicSignKey,
          encPublicKey: profile.publicEncKey,
          displayName: profile.displayName,
          username: profile.username
        });
      } catch {
        continue;
      }
    }

    const unread = unreadCounts[userId] || 0;
    const isOnline = onlineUsers.has(userId);

    const card = document.createElement('div');
    card.className = `contact-card ${currentChatUser?.id === userId ? 'active' : ''}`;
    card.dataset.userId = userId;
    card.innerHTML = `
      <div class="contact-avatar ${isOnline ? 'online' : ''}">
        ${(userInfo.displayName || userInfo.username || '?')[0].toUpperCase()}
      </div>
      <div class="contact-info">
        <div class="contact-name">${escapeHtml(userInfo.displayName || userInfo.username || 'Unknown')}</div>
        <div class="contact-status">${isOnline ? 'online' : 'offline'}</div>
      </div>
      ${unread > 0 ? `<div class="unread-badge">${unread}</div>` : ''}
    `;

    card.addEventListener('click', () => openChat(userId));
    listEl.appendChild(card);
  }
}

async function loadRecentContacts() {
  // Preload public keys for recent contacts
  const recentChats = JSON.parse(localStorage.getItem('necromansa_recent_chats') || '[]');
  for (const userId of recentChats) {
    if (!getCachedPublicKey(userId)) {
      try {
        const profile = await getUserProfile(userId);
        cachePublicKey(userId, {
          signPublicKey: profile.publicSignKey,
          encPublicKey: profile.publicEncKey,
          displayName: profile.displayName,
          username: profile.username
        });
      } catch {}
    }
  }
}

// Open chat with a user
async function openChat(userId) {
  currentChatUser = await getUserProfile(userId);
  cachePublicKey(userId, {
    signPublicKey: currentChatUser.publicSignKey,
    encPublicKey: currentChatUser.publicEncKey,
    displayName: currentChatUser.displayName,
    username: currentChatUser.username
  });

  // Add to recent chats
  let recent = JSON.parse(localStorage.getItem('necromansa_recent_chats') || '[]');
  recent = [userId, ...recent.filter(id => id !== userId)].slice(0, 20);
  localStorage.setItem('necromansa_recent_chats', JSON.stringify(recent));

  // Clear unread
  unreadCounts[userId] = 0;
  markRead(userId);

  // Load messages
  chatMessages = await loadMessages(userId);

  renderChatView();
  renderContactsList();
}

function renderChatView() {
  const chatViewEl = document.getElementById('chat-view');
  if (!chatViewEl || !currentChatUser) return;

  const isOnline = onlineUsers.has(currentChatUser.id);

  chatViewEl.innerHTML = `
    <div class="chat-header">
      <button class="btn-back" id="btn-back-contacts">[ < ]</button>
      <div class="chat-header-info">
        <div class="chat-header-name">${escapeHtml(currentChatUser.displayName)}</div>
        <div class="chat-header-status ${isOnline ? 'online' : 'offline'}">${isOnline ? 'online' : '@' + currentChatUser.username}</div>
      </div>
      <button class="btn-icon" id="btn-chat-profile" title="View profile">[ ... ]</button>
    </div>
    <div class="chat-messages" id="chat-messages">
      <div class="chat-encryption-notice">
        <span class="lock-icon">[E2E]</span>
        Messages are end-to-end encrypted. Server cannot read them.
      </div>
    </div>
    <div class="typing-indicator hidden" id="typing-indicator">
      <span class="typing-dot"></span>
      <span class="typing-dot"></span>
      <span class="typing-dot"></span>
    </div>
    <div class="chat-input-area">
      <button class="btn-icon btn-attach" id="btn-attach-image" title="Send image">[ + ]</button>
      <button class="btn-icon btn-emoji" id="btn-emoji" title="Emoji">[ : ) ]</button>
      <div id="emoji-picker" class="emoji-picker hidden"></div>
      <input type="file" id="chat-image-input" accept="image/*" class="hidden">
      <input type="text" id="chat-input" class="chat-input" placeholder="Type a message..." autocomplete="off">
      <button class="btn-send" id="btn-send-message">[ > ]</button>
    </div>
  `;

  // Render messages
  const messagesEl = document.getElementById('chat-messages');
  for (const msg of chatMessages) {
    appendMessage(msg, false);
  }
  scrollToBottom();

  // Event listeners
  document.getElementById('btn-back-contacts').addEventListener('click', () => {
    currentChatUser = null;
    document.getElementById('chat-view').classList.add('hidden');
    document.getElementById('contacts-panel').classList.remove('hidden');
  });

  document.getElementById('btn-send-message').addEventListener('click', handleSendMessage);

  const inputEl = document.getElementById('chat-input');
  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  });

  inputEl.addEventListener('input', () => {
    debouncedTyping(currentChatUser.id);
  });

  document.getElementById('btn-attach-image').addEventListener('click', () => {
    document.getElementById('chat-image-input').click();
  });

  document.getElementById('chat-image-input').addEventListener('change', handleSendImage);

  document.getElementById('btn-chat-profile').addEventListener('click', () => {
    showUserProfile(currentChatUser);
  });

  // Emoji picker
  const emojiBtn = document.getElementById('btn-emoji');
  const emojiPicker = document.getElementById('emoji-picker');
  const emojiList = ['😀','😂','😍','🥰','😎','🤔','👍','👋','❤️','🔥','✨','💯','🎉','😢','😤','🙏','💪','🤝','👀','💬','📱','💻','⚡','🛡️','🔑','🎵','🚀','⭐','🌟','💜'];
  emojiPicker.innerHTML = emojiList.map(e => `<button class="emoji-btn" data-emoji="${e}">${e}</button>`).join('');
  emojiBtn.addEventListener('click', () => {
    emojiPicker.classList.toggle('hidden');
  });
  emojiPicker.querySelectorAll('.emoji-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = document.getElementById('chat-input');
      input.value += btn.dataset.emoji;
      input.focus();
      emojiPicker.classList.add('hidden');
    });
  });
  // Close emoji picker when clicking outside
  document.addEventListener('click', (e) => {
    if (!emojiPicker.contains(e.target) && e.target !== emojiBtn) {
      emojiPicker.classList.add('hidden');
    }
  });

  // Show chat view
  document.getElementById('contacts-panel').classList.add('hidden');
  chatViewEl.classList.remove('hidden');
}

async function handleSendMessage() {
  const inputEl = document.getElementById('chat-input');
  const text = inputEl.value.trim();
  if (!text || !currentChatUser) return;

  inputEl.value = '';

  const tempId = await sendMessage(currentChatUser.id, text);

  // Show message locally
  const localMsg = {
    id: null,
    tempId,
    senderId: getCurrentUserId(),
    recipientId: currentChatUser.id,
    plaintext: text,
    isOwn: true,
    createdAt: new Date().toISOString(),
    sending: true
  };

  chatMessages.push(localMsg);
  appendMessage(localMsg);
  scrollToBottom();
}

async function handleSendImage(e) {
  const file = e.target.files[0];
  if (!file || !currentChatUser) return;

  if (file.size > 5 * 1024 * 1024) {
    alert('Image must be under 5MB');
    return;
  }

  e.target.value = '';

  try {
    const tempId = await sendImageMessage(currentChatUser.id, file);

    const localMsg = {
      id: null,
      tempId,
      senderId: getCurrentUserId(),
      recipientId: currentChatUser.id,
      plaintext: `[Image: ${file.name}]`,
      isOwn: true,
      createdAt: new Date().toISOString(),
      sending: true,
      isImage: true,
      imageUrl: URL.createObjectURL(file)
    };

    chatMessages.push(localMsg);
    appendMessage(localMsg);
    scrollToBottom();
  } catch (err) {
    console.error('Failed to send image:', err);
  }
}

function appendMessage(msg, animate = true) {
  const messagesEl = document.getElementById('chat-messages');
  if (!messagesEl) return;

  const div = document.createElement('div');
  div.className = `message ${msg.isOwn ? 'own' : 'other'} ${animate ? 'animate-in' : ''} ${msg.sending ? 'sending' : ''} ${msg.decryptError ? 'error' : ''}`;
  if (msg.tempId) div.dataset.tempId = msg.tempId;
  if (msg.id) div.dataset.messageId = msg.id;

  const time = new Date(msg.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  let content = '';
  if (msg.isImage && msg.imageUrl) {
    content = `<div class="msg-image"><img src="${msg.imageUrl}" alt="image"></div>`;
  } else if (msg.decryptError) {
    content = `<div class="msg-text error">[Decryption failed]</div>`;
  } else {
    content = `<div class="msg-text">${escapeHtml(msg.plaintext)}</div>`;
  }

  let receiptHtml = '';
  if (msg.isOwn && !msg.sending) {
    if (msg.read) {
      receiptHtml = '<span class="receipt read"><span class="check">&#10003;</span><span class="check">&#10003;</span></span>';
    } else if (msg.delivered) {
      receiptHtml = '<span class="receipt delivered"><span class="check">&#10003;</span><span class="check">&#10003;</span></span>';
    } else {
      receiptHtml = '<span class="receipt sent"><span class="check">&#10003;</span></span>';
    }
  }

  div.innerHTML = `
    ${content}
    <div class="msg-meta">
      <span class="msg-time">${time}</span>
      ${msg.isOwn ? `<span class="msg-status">${msg.sending ? '<span class="receipt sending"><span class="check spinning">&#9675;</span></span>' : receiptHtml}</span>` : ''}
      ${msg.isOwn && msg.id && !msg.sending ? `<button class="btn-delete-msg" data-msg-id="${msg.id}" title="Delete message">[x]</button>` : ''}
    </div>
  `;

  // Add delete handler
  const deleteBtn = div.querySelector('.btn-delete-msg');
  if (deleteBtn) {
    deleteBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const msgId = parseInt(deleteBtn.dataset.msgId);
      if (msgId) {
        deleteMessage(msgId);
        chatMessages = chatMessages.filter(m => m.id !== msgId);
        div.style.animation = 'msgDelete 0.3s ease forwards';
        setTimeout(() => div.remove(), 300);
      }
    });
  }

  messagesEl.appendChild(div);
}

function scrollToBottom() {
  const messagesEl = document.getElementById('chat-messages');
  if (messagesEl) {
    requestAnimationFrame(() => {
      messagesEl.scrollTop = messagesEl.scrollHeight;
    });
  }
}

function showTypingIndicator() {
  const el = document.getElementById('typing-indicator');
  if (el) el.classList.remove('hidden');
}

function hideTypingIndicator() {
  const el = document.getElementById('typing-indicator');
  if (el) el.classList.add('hidden');
}

function updateChatHeader() {
  if (!currentChatUser) return;
  const statusEl = document.querySelector('.chat-header-status');
  if (statusEl) {
    const isOnline = onlineUsers.has(currentChatUser.id);
    statusEl.textContent = isOnline ? 'online' : '@' + currentChatUser.username;
    statusEl.className = `chat-header-status ${isOnline ? 'online' : 'offline'}`;
  }
}

function showUserProfile(user) {
  const modal = document.getElementById('user-profile-modal');
  if (!modal) return;

  const isOnline = onlineUsers.has(user.id);
  const isOwn = user.id === getCurrentUserId();

  modal.innerHTML = `
    <div class="modal-content">
      <div class="modal-header">
        <h2>${isOwn ? 'MY_PROFILE' : 'USER_PROFILE'}</h2>
        <span class="modal-close" id="btn-close-profile">[X]</span>
      </div>
      <div class="profile-content">
        <div class="profile-avatar">${(user.displayName || '?')[0].toUpperCase()}</div>
        ${isOwn ? `
          <div class="profile-edit-form">
            <div class="input-group">
              <span class="input-prefix">name:</span>
              <input type="text" id="edit-display-name" class="input-field" value="${escapeHtml(user.displayName || '')}" placeholder="Display name">
            </div>
            <div class="input-group">
              <span class="input-prefix">bio:</span>
              <input type="text" id="edit-bio" class="input-field" value="${escapeHtml(user.bio || '')}" placeholder="Tell something about yourself">
            </div>
            <button id="btn-save-profile" class="btn-primary">[ SAVE_PROFILE ]</button>
            <p id="profile-edit-error" class="error-text"></p>
          </div>
        ` : `
          <div class="profile-name">${escapeHtml(user.displayName)}</div>
          <div class="profile-username">@${escapeHtml(user.username)}</div>
          <div class="profile-status ${isOnline ? 'online' : 'offline'}">${isOnline ? 'Online' : 'Offline'}</div>
          ${user.bio ? `<div class="profile-bio">${escapeHtml(user.bio)}</div>` : ''}
        `}
        <div class="profile-keys">
          <div class="key-label">Signing Key:</div>
          <div class="key-value">${(user.publicSignKey || '').slice(0, 20)}...</div>
          <div class="key-label">Encryption Key:</div>
          <div class="key-value">${(user.publicEncKey || '').slice(0, 20)}...</div>
        </div>
      </div>
    </div>
  `;

  modal.classList.remove('hidden');
  document.getElementById('btn-close-profile').addEventListener('click', () => {
    modal.classList.add('hidden');
  });

  if (isOwn) {
    document.getElementById('btn-save-profile').addEventListener('click', async () => {
      const newName = document.getElementById('edit-display-name').value.trim();
      const newBio = document.getElementById('edit-bio').value.trim();
      const errorEl = document.getElementById('profile-edit-error');

      if (!newName) {
        errorEl.textContent = 'Display name required';
        return;
      }

      try {
        const btn = document.getElementById('btn-save-profile');
        btn.disabled = true;
        btn.textContent = '[ SAVING... ]';

        await updateProfile(newName, newBio);

        // Update local session
        const session = loadChatSession();
        if (session) {
          session.displayName = newName;
          saveChatSession(session);
        }

        // Update current chat user
        currentChatUser = { ...currentChatUser, displayName: newName, bio: newBio };

        modal.classList.add('hidden');
      } catch (err) {
        errorEl.textContent = err.message;
        const btn = document.getElementById('btn-save-profile');
        btn.disabled = false;
        btn.textContent = '[ SAVE_PROFILE ]';
      }
    });
  }
}

function showNotification(msg) {
  if (Notification.permission === 'granted') {
    new Notification('NECROMANSA', {
      body: 'New encrypted message',
      icon: '/favicon.ico'
    });
  }
}

// Search UI
export function initSearchUI() {
  const searchInput = document.getElementById('search-contacts');
  const searchResults = document.getElementById('search-results');
  if (!searchInput || !searchResults) return;

  let searchTimeout = null;

  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    const query = searchInput.value.trim();

    if (query.length < 1) {
      searchResults.innerHTML = '';
      searchResults.classList.add('hidden');
      return;
    }

    searchTimeout = setTimeout(async () => {
      try {
        const users = await searchUsers(query);
        renderSearchResults(users);
      } catch (err) {
        console.error('Search failed:', err);
      }
    }, 300);
  });

  searchInput.addEventListener('blur', () => {
    setTimeout(() => {
      searchResults.classList.add('hidden');
    }, 200);
  });
}

function renderSearchResults(users) {
  const resultsEl = document.getElementById('search-results');
  if (!resultsEl) return;

  resultsEl.innerHTML = '';

  const myId = getCurrentUserId();
  const filtered = users.filter(u => u.id !== myId);

  if (filtered.length === 0) {
    resultsEl.innerHTML = '<div class="search-empty">No users found</div>';
    resultsEl.classList.remove('hidden');
    return;
  }

  for (const user of filtered) {
    cachePublicKey(user.id, {
      signPublicKey: user.publicSignKey,
      encPublicKey: user.publicEncKey,
      displayName: user.displayName,
      username: user.username
    });

    const isOnline = onlineUsers.has(user.id);

    const item = document.createElement('div');
    item.className = 'search-result-item';
    item.innerHTML = `
      <div class="contact-avatar ${isOnline ? 'online' : ''}">${user.displayName[0].toUpperCase()}</div>
      <div class="contact-info">
        <div class="contact-name">${escapeHtml(user.displayName)}</div>
        <div class="contact-username">@${escapeHtml(user.username)}</div>
      </div>
    `;

    item.addEventListener('click', () => {
      resultsEl.classList.add('hidden');
      document.getElementById('search-contacts').value = '';
      openChat(user.id);
    });

    resultsEl.appendChild(item);
  }

  resultsEl.classList.remove('hidden');
}

// Logout
export function logoutChat() {
  disconnectSocket();
  clearChatSession();
  currentChatUser = null;
  chatMessages = [];
  onlineUsers.clear();
  unreadCounts = {};
  showAuthScreen();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
