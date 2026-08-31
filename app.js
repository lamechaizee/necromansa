(() => {
    'use strict';

    // --- Crypto helpers ---
    const SALT_KEY = 'necromansa_salt';
    const DATA_KEY = 'necromansa_data';

    function getSalt() {
        let salt = localStorage.getItem(SALT_KEY);
        if (!salt) {
            const arr = crypto.getRandomValues(new Uint8Array(16));
            salt = btoa(String.fromCharCode(...arr));
            localStorage.setItem(SALT_KEY, salt);
        }
        return Uint8Array.from(atob(salt), c => c.charCodeAt(0));
    }

    async function deriveKey(pin) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: getSalt(), iterations: 100000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function encrypt(data, pin) {
        const key = await deriveKey(pin);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const enc = new TextEncoder();
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(data))
        );
        return {
            iv: btoa(String.fromCharCode(...iv)),
            data: btoa(String.fromCharCode(...new Uint8Array(encrypted)))
        };
    }

    async function decrypt(payload, pin) {
        const key = await deriveKey(pin);
        const iv = Uint8Array.from(atob(payload.iv), c => c.charCodeAt(0));
        const data = Uint8Array.from(atob(payload.data), c => c.charCodeAt(0));
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv }, key, data
        );
        return JSON.parse(new TextDecoder().decode(decrypted));
    }

    // --- Hash PIN for verification (not the encryption key itself) ---
    async function hashPin(pin) {
        const enc = new TextEncoder();
        const hash = await crypto.subtle.digest('SHA-256', enc.encode(pin + getSalt()));
        return btoa(String.fromCharCode(...new Uint8Array(hash)));
    }

    // --- State ---
    let currentPin = null;
    let vaultData = { links: [], notes: [] };

    // --- DOM refs ---
    const $ = id => document.getElementById(id);
    const loginScreen = $('login-screen');
    const appScreen = $('app-screen');
    const setupSection = $('setup-section');
    const loginSection = $('login-section');
    const loginError = $('login-error');
    const newPin = $('new-pin');
    const confirmPin = $('confirm-pin');
    const enterPin = $('enter-pin');
    const linksList = $('links-list');
    const notesList = $('notes-list');
    const editModal = $('edit-modal');
    const modalTitle = $('modal-title');
    const modalFields = $('modal-fields');

    // --- Init ---
    function init() {
        const hasVault = localStorage.getItem(DATA_KEY);
        if (hasVault) {
            loginSection.classList.remove('hidden');
        } else {
            setupSection.classList.remove('hidden');
        }
        bindEvents();
    }

    function bindEvents() {
        $('btn-create-pin').addEventListener('click', createVault);
        $('btn-unlock').addEventListener('click', unlockVault);
        $('btn-lock').addEventListener('click', lockVault);
        $('btn-export').addEventListener('click', exportData);
        $('btn-import').addEventListener('click', () => $('import-file').click());
        $('import-file').addEventListener('change', importData);

        // Tabs
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => switchTab(tab.dataset.tab));
        });

        // Add items
        $('btn-add-link').addEventListener('click', addLink);
        $('btn-add-note').addEventListener('click', addNote);

        // Search
        $('search-links').addEventListener('input', () => renderLinks());
        $('search-notes').addEventListener('input', () => renderNotes());

        // Modal
        $('btn-modal-cancel').addEventListener('click', closeModal);
        $('btn-modal-save').addEventListener('click', saveModal);

        // Enter key on PIN inputs
        newPin.addEventListener('keydown', e => { if (e.key === 'Enter') confirmPin.focus(); });
        confirmPin.addEventListener('keydown', e => { if (e.key === 'Enter') createVault(); });
        enterPin.addEventListener('keydown', e => { if (e.key === 'Enter') unlockVault(); });
    }

    // --- Vault ---
    async function createVault() {
        const pin = newPin.value.trim();
        const confirm = confirmPin.value.trim();

        if (pin.length < 4 || pin.length > 6 || !/^\d+$/.test(pin)) {
            showError('PIN must be 4-6 digits');
            return;
        }
        if (pin !== confirm) {
            showError('PINs do not match');
            return;
        }

        const pinHash = await hashPin(pin);
        const encrypted = await encrypt({ links: [], notes: [] }, pin);
        localStorage.setItem(DATA_KEY, JSON.stringify({ hash: pinHash, payload: encrypted }));
        currentPin = pin;
        vaultData = { links: [], notes: [] };
        showApp();
    }

    async function unlockVault() {
        const pin = enterPin.value.trim();
        if (!pin) return;

        try {
            const stored = JSON.parse(localStorage.getItem(DATA_KEY));
            const pinHash = await hashPin(pin);

            if (pinHash !== stored.hash) {
                showError('Wrong PIN');
                return;
            }

            vaultData = await decrypt(stored.payload, pin);
            currentPin = pin;
            showApp();
        } catch {
            showError('Wrong PIN or corrupted data');
        }
    }

    function lockVault() {
        currentPin = null;
        vaultData = { links: [], notes: [] };
        enterPin.value = '';
        appScreen.classList.remove('active');
        loginScreen.classList.add('active');
        loginSection.classList.remove('hidden');
        setupSection.classList.add('hidden');
        loginError.textContent = '';
    }

    async function saveVault() {
        if (!currentPin) return;
        const encrypted = await encrypt(vaultData, currentPin);
        const pinHash = await hashPin(currentPin);
        localStorage.setItem(DATA_KEY, JSON.stringify({ hash: pinHash, payload: encrypted }));
    }

    function showApp() {
        loginScreen.classList.remove('active');
        appScreen.classList.add('active');
        renderLinks();
        renderNotes();
    }

    function showError(msg) {
        loginError.textContent = msg;
        setTimeout(() => { loginError.textContent = ''; }, 3000);
    }

    // --- Tabs ---
    function switchTab(tab) {
        document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === `tab-${tab}`));
    }

    // --- Links ---
    function addLink() {
        const title = $('link-title').value.trim();
        const url = $('link-url').value.trim();
        const tags = $('link-tags').value.split(',').map(t => t.trim()).filter(Boolean);

        if (!title || !url) return;

        vaultData.links.unshift({
            id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
            title, url, tags, created: new Date().toISOString()
        });

        $('link-title').value = '';
        $('link-url').value = '';
        $('link-tags').value = '';
        saveVault();
        renderLinks();
    }

    function renderLinks() {
        const query = $('search-links').value.toLowerCase();
        const filtered = vaultData.links.filter(l =>
            l.title.toLowerCase().includes(query) ||
            l.url.toLowerCase().includes(query) ||
            l.tags.some(t => t.toLowerCase().includes(query))
        );

        if (filtered.length === 0) {
            linksList.innerHTML = '<div class="empty-state">No links yet</div>';
            return;
        }

        linksList.innerHTML = filtered.map(link => `
            <div class="item-card" data-id="${link.id}">
                <div class="item-header">
                    <span class="item-title">${esc(link.title)}</span>
                    <div class="item-actions">
                        <button class="btn-edit" onclick="app.editLink('${link.id}')">Edit</button>
                        <button class="btn-danger" onclick="app.deleteLink('${link.id}')">Delete</button>
                    </div>
                </div>
                <a href="${esc(link.url)}" target="_blank" rel="noopener" class="item-url">${esc(link.url)}</a>
                ${link.tags.length ? `<div class="item-tags">${link.tags.map(t => `<span class="tag">${esc(t)}</span>`).join('')}</div>` : ''}
                <div class="item-date">${formatDate(link.created)}</div>
            </div>
        `).join('');
    }

    function deleteLink(id) {
        vaultData.links = vaultData.links.filter(l => l.id !== id);
        saveVault();
        renderLinks();
    }

    function editLink(id) {
        const link = vaultData.links.find(l => l.id === id);
        if (!link) return;

        modalTitle.textContent = 'Edit Link';
        modalFields.innerHTML = `
            <input type="text" id="edit-link-title" class="input-field" value="${esc(link.title)}" placeholder="Title">
            <input type="url" id="edit-link-url" class="input-field" value="${esc(link.url)}" placeholder="https://...">
            <input type="text" id="edit-link-tags" class="input-field" value="${esc(link.tags.join(', '))}" placeholder="Tags">
        `;
        editModal.classList.remove('hidden');
        editModal.dataset.type = 'link';
        editModal.dataset.id = id;
    }

    // --- Notes ---
    function addNote() {
        const title = $('note-title').value.trim();
        const content = $('note-content').value.trim();
        const tags = $('note-tags').value.split(',').map(t => t.trim()).filter(Boolean);

        if (!title) return;

        vaultData.notes.unshift({
            id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
            title, content, tags, created: new Date().toISOString()
        });

        $('note-title').value = '';
        $('note-content').value = '';
        $('note-tags').value = '';
        saveVault();
        renderNotes();
    }

    function renderNotes() {
        const query = $('search-notes').value.toLowerCase();
        const filtered = vaultData.notes.filter(n =>
            n.title.toLowerCase().includes(query) ||
            n.content.toLowerCase().includes(query) ||
            n.tags.some(t => t.toLowerCase().includes(query))
        );

        if (filtered.length === 0) {
            notesList.innerHTML = '<div class="empty-state">No notes yet</div>';
            return;
        }

        notesList.innerHTML = filtered.map(note => `
            <div class="item-card" data-id="${note.id}">
                <div class="item-header">
                    <span class="item-title">${esc(note.title)}</span>
                    <div class="item-actions">
                        <button class="btn-edit" onclick="app.editNote('${note.id}')">Edit</button>
                        <button class="btn-danger" onclick="app.deleteNote('${note.id}')">Delete</button>
                    </div>
                </div>
                ${note.content ? `<div class="item-content">${esc(note.content)}</div>` : ''}
                ${note.tags.length ? `<div class="item-tags">${note.tags.map(t => `<span class="tag">${esc(t)}</span>`).join('')}</div>` : ''}
                <div class="item-date">${formatDate(note.created)}</div>
            </div>
        `).join('');
    }

    function deleteNote(id) {
        vaultData.notes = vaultData.notes.filter(n => n.id !== id);
        saveVault();
        renderNotes();
    }

    function editNote(id) {
        const note = vaultData.notes.find(n => n.id === id);
        if (!note) return;

        modalTitle.textContent = 'Edit Note';
        modalFields.innerHTML = `
            <input type="text" id="edit-note-title" class="input-field" value="${esc(note.title)}" placeholder="Title">
            <textarea id="edit-note-content" class="input-field textarea-field" rows="5" placeholder="Note content">${esc(note.content)}</textarea>
            <input type="text" id="edit-note-tags" class="input-field" value="${esc(note.tags.join(', '))}" placeholder="Tags">
        `;
        editModal.classList.remove('hidden');
        editModal.dataset.type = 'note';
        editModal.dataset.id = id;
    }

    // --- Modal ---
    function closeModal() {
        editModal.classList.add('hidden');
    }

    function saveModal() {
        const type = editModal.dataset.type;
        const id = editModal.dataset.id;

        if (type === 'link') {
            const link = vaultData.links.find(l => l.id === id);
            if (link) {
                link.title = $('edit-link-title').value.trim() || link.title;
                link.url = $('edit-link-url').value.trim() || link.url;
                link.tags = $('edit-link-tags').value.split(',').map(t => t.trim()).filter(Boolean);
            }
            renderLinks();
        } else if (type === 'note') {
            const note = vaultData.notes.find(n => n.id === id);
            if (note) {
                note.title = $('edit-note-title').value.trim() || note.title;
                note.content = $('edit-note-content').value.trim();
                note.tags = $('edit-note-tags').value.split(',').map(t => t.trim()).filter(Boolean);
            }
            renderNotes();
        }

        saveVault();
        closeModal();
    }

    // --- Import / Export ---
    function exportData() {
        const blob = new Blob([JSON.stringify(vaultData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `necromansa-backup-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    async function importData(e) {
        const file = e.target.files[0];
        if (!file) return;

        try {
            const text = await file.text();
            const imported = JSON.parse(text);
            if (imported.links && imported.notes) {
                vaultData = imported;
                await saveVault();
                renderLinks();
                renderNotes();
            }
        } catch {
            alert('Invalid backup file');
        }
        e.target.value = '';
    }

    // --- Helpers ---
    function esc(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function formatDate(iso) {
        const d = new Date(iso);
        return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
    }

    // --- Expose for inline onclick ---
    window.app = { editLink, deleteLink, editNote, deleteNote };

    // --- Start ---
    init();
})();
