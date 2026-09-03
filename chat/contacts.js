// NECROMANSA Contacts Module
// User search, profiles, contact list

const API_BASE = window.NECROMANSA_API || '';

let authToken = null;
let currentUserId = null;

export function setAuth(token, userId) {
  authToken = token;
  currentUserId = userId;
}

export function getAuthToken() {
  return authToken;
}

export function getCurrentUserId() {
  return currentUserId;
}

async function apiFetch(path, options = {}) {
  const res = await fetch(`${API_BASE}/api${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      ...options.headers
    }
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }));
    throw new Error(err.error || 'Request failed');
  }

  return res.json();
}

// Register new user
export async function register(username, displayName, password, publicSignKey, publicEncKey) {
  const data = await apiFetch('/users/register', {
    method: 'POST',
    body: JSON.stringify({ username, displayName, password, publicSignKey, publicEncKey })
  });
  authToken = data.token;
  currentUserId = data.user.id;
  return data;
}

// Login
export async function login(username, password) {
  const data = await apiFetch('/users/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  });
  authToken = data.token;
  currentUserId = data.user.id;
  return data;
}

// Search users
export async function searchUsers(query) {
  if (!query || query.length < 1) return [];
  return apiFetch(`/users/search?q=${encodeURIComponent(query)}`);
}

// Get user profile
export async function getUserProfile(userId) {
  return apiFetch(`/users/${userId}`);
}

// Update own profile
export async function updateProfile(displayName, bio) {
  return apiFetch('/users/profile', {
    method: 'PUT',
    body: JSON.stringify({ displayName, bio })
  });
}

// Get message history
export async function getMessages(userId, limit = 50, before = null) {
  let url = `/messages/${userId}?limit=${limit}`;
  if (before) url += `&before=${before}`;
  return apiFetch(url);
}

// Mark messages as read
export async function markMessagesRead(userId) {
  return apiFetch(`/messages/${userId}/read`, { method: 'POST' });
}

// Get unread counts
export async function getUnreadCounts() {
  return apiFetch('/messages/unread/counts');
}

// Save chat session to localStorage
export function saveChatSession(session) {
  localStorage.setItem('necromansa_chat_session', JSON.stringify(session));
}

// Load chat session from localStorage
export function loadChatSession() {
  try {
    const data = localStorage.getItem('necromansa_chat_session');
    return data ? JSON.parse(data) : null;
  } catch {
    return null;
  }
}

// Clear chat session
export function clearChatSession() {
  localStorage.removeItem('necromansa_chat_session');
}
