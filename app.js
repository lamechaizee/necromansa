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

    // --- IndexedDB for image blobs ---
    const DB_NAME = 'necromansa_images';
    const DB_STORE = 'blobs';
    const MAX_IMAGE_SIZE = 5 * 1024 * 1024; // 5MB

    function openDB() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(DB_NAME, 1);
            req.onupgradeneeded = () => {
                req.result.createObjectStore(DB_STORE);
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    }

    async function dbPut(key, value) {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(DB_STORE, 'readwrite');
            tx.objectStore(DB_STORE).put(value, key);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async function dbGet(key) {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(DB_STORE, 'readonly');
            const req = tx.objectStore(DB_STORE).get(key);
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    }

    async function dbDelete(key) {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(DB_STORE, 'readwrite');
            tx.objectStore(DB_STORE).delete(key);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    // --- Encrypt/decrypt image blob for IndexedDB storage ---
    async function encryptBlob(blob, pin) {
        const buffer = await blob.arrayBuffer();
        const key = await deriveKey(pin);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv }, key, buffer
        );
        return { iv, data: new Uint8Array(encrypted) };
    }

    async function decryptBlob(encryptedObj, pin, mimeType) {
        const key = await deriveKey(pin);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: encryptedObj.iv }, key, encryptedObj.data
        );
        return new Blob([decrypted], { type: mimeType });
    }

    // --- State ---
    let currentPin = null;
    let vaultData = { links: [], notes: [], images: [] };

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
    const imagesList = $('images-list');
    const editModal = $('edit-modal');
    const modalTitle = $('modal-title');
    const modalFields = $('modal-fields');
    const imageViewer = $('image-viewer');
    const viewerTitle = $('viewer-title');
    const viewerImg = $('viewer-img');
    let pendingImageData = null; // holds { blob, dataUrl } before upload
    let currentViewerImageId = null;

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
        $('btn-add-image').addEventListener('click', addImage);

        // Search
        $('search-links').addEventListener('input', () => renderLinks());
        $('search-notes').addEventListener('input', () => renderNotes());
        $('search-images').addEventListener('input', () => renderImages());

        // Modal
        $('btn-modal-cancel').addEventListener('click', closeModal);
        $('btn-modal-cancel-btn').addEventListener('click', closeModal);
        $('btn-modal-save').addEventListener('click', saveModal);

        // Image viewer
        $('btn-viewer-close').addEventListener('click', closeViewer);
        $('btn-viewer-download').addEventListener('click', downloadImage);
        imageViewer.addEventListener('click', e => { if (e.target === imageViewer) closeViewer(); });

        // Image upload
        const uploadArea = $('upload-area');
        const imageFile = $('image-file');
        uploadArea.addEventListener('click', () => { if (!pendingImageData) imageFile.click(); });
        imageFile.addEventListener('change', handleImageSelect);
        $('btn-clear-preview').addEventListener('click', e => { e.stopPropagation(); clearImagePreview(); });

        // Drag and drop
        uploadArea.addEventListener('dragover', e => { e.preventDefault(); uploadArea.classList.add('dragover'); });
        uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('dragover'));
        uploadArea.addEventListener('drop', e => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const file = e.dataTransfer.files[0];
            if (file && file.type.startsWith('image/')) processImageFile(file);
        });

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
            showError('ERR: KEY MUST BE 4-6 DIGITS');
            return;
        }
        if (pin !== confirm) {
            showError('ERR: KEYS DO NOT MATCH');
            return;
        }

        const pinHash = await hashPin(pin);
        const encrypted = await encrypt({ links: [], notes: [], images: [] }, pin);
        localStorage.setItem(DATA_KEY, JSON.stringify({ hash: pinHash, payload: encrypted }));
        currentPin = pin;
        vaultData = { links: [], notes: [], images: [] };
        showApp();
    }

    async function unlockVault() {
        const pin = enterPin.value.trim();
        if (!pin) return;

        try {
            const stored = JSON.parse(localStorage.getItem(DATA_KEY));
            const pinHash = await hashPin(pin);

            if (pinHash !== stored.hash) {
                showError('ERR: ACCESS DENIED');
                return;
            }

            vaultData = await decrypt(stored.payload, pin);
            if (!vaultData.images) vaultData.images = [];
            currentPin = pin;
            showApp();
        } catch {
            showError('ERR: DECRYPTION FAILED');
        }
    }

    function lockVault() {
        currentPin = null;
        vaultData = { links: [], notes: [], images: [] };
        enterPin.value = '';
        pendingImageData = null;
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
        renderImages();
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
            linksList.innerHTML = '<div class="empty-state">NO LINKS IN VAULT</div>';
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

        modalTitle.textContent = 'EDIT_LINK';
        modalFields.innerHTML = `
            <div class="input-group">
                <span class="input-prefix">title:</span>
                <input type="text" id="edit-link-title" class="input-field" value="${esc(link.title)}" placeholder="entry title">
            </div>
            <div class="input-group">
                <span class="input-prefix">url:</span>
                <input type="url" id="edit-link-url" class="input-field" value="${esc(link.url)}" placeholder="https://">
            </div>
            <div class="input-group">
                <span class="input-prefix">tags:</span>
                <input type="text" id="edit-link-tags" class="input-field" value="${esc(link.tags.join(', '))}" placeholder="tag1, tag2">
            </div>
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
            notesList.innerHTML = '<div class="empty-state">NO NOTES IN VAULT</div>';
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

        modalTitle.textContent = 'EDIT_NOTE';
        modalFields.innerHTML = `
            <div class="input-group">
                <span class="input-prefix">title:</span>
                <input type="text" id="edit-note-title" class="input-field" value="${esc(note.title)}" placeholder="note title">
            </div>
            <div class="input-group">
                <span class="input-prefix">data:</span>
                <textarea id="edit-note-content" class="input-field textarea-field" rows="5" placeholder="write your note...">${esc(note.content)}</textarea>
            </div>
            <div class="input-group">
                <span class="input-prefix">tags:</span>
                <input type="text" id="edit-note-tags" class="input-field" value="${esc(note.tags.join(', '))}" placeholder="tag1, tag2">
            </div>
        `;
        editModal.classList.remove('hidden');
        editModal.dataset.type = 'note';
        editModal.dataset.id = id;
    }

    // --- Images ---
    function handleImageSelect(e) {
        const file = e.target.files[0];
        if (file) processImageFile(file);
        e.target.value = '';
    }

    function processImageFile(file) {
        if (file.size > MAX_IMAGE_SIZE) {
            alert('ERR: FILE TOO LARGE (MAX 5MB)');
            return;
        }
        if (!file.type.startsWith('image/')) {
            alert('ERR: NOT AN IMAGE FILE');
            return;
        }

        const reader = new FileReader();
        reader.onload = () => {
            pendingImageData = { blob: file, dataUrl: reader.result, mimeType: file.type };
            $('preview-img').src = reader.result;
            $('upload-preview').classList.remove('hidden');
            $('upload-area').querySelector('.upload-prompt').classList.add('hidden');
        };
        reader.readAsDataURL(file);
    }

    function clearImagePreview() {
        pendingImageData = null;
        $('preview-img').src = '';
        $('upload-preview').classList.add('hidden');
        $('upload-area').querySelector('.upload-prompt').classList.remove('hidden');
    }

    async function addImage() {
        if (!pendingImageData) {
            alert('ERR: NO IMAGE SELECTED');
            return;
        }

        const title = $('image-title').value.trim() || 'Untitled';
        const tags = $('image-tags').value.split(',').map(t => t.trim()).filter(Boolean);
        const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

        // Encrypt and store blob in IndexedDB
        const encrypted = await encryptBlob(pendingImageData.blob, currentPin);
        await dbPut(id, { encrypted, mimeType: pendingImageData.mimeType });

        // Store metadata in vault
        vaultData.images.unshift({
            id, title, tags, mimeType: pendingImageData.mimeType,
            size: pendingImageData.blob.size,
            created: new Date().toISOString()
        });

        $('image-title').value = '';
        $('image-tags').value = '';
        clearImagePreview();
        saveVault();
        renderImages();
    }

    async function renderImages() {
        const query = $('search-images').value.toLowerCase();
        const filtered = vaultData.images.filter(img =>
            img.title.toLowerCase().includes(query) ||
            img.tags.some(t => t.toLowerCase().includes(query))
        );

        if (filtered.length === 0) {
            imagesList.innerHTML = '<div class="empty-state">NO IMAGES IN VAULT</div>';
            return;
        }

        // Render cards with placeholder, then load thumbnails
        imagesList.innerHTML = filtered.map(img => `
            <div class="image-card" data-id="${img.id}">
                <div class="image-thumb-wrap" onclick="app.viewImage('${img.id}')">
                    <img src="" alt="${esc(img.title)}" data-img-id="${img.id}" class="image-thumb">
                </div>
                <div class="image-card-info">
                    <div class="image-card-title">${esc(img.title)}</div>
                    <div class="image-card-meta">
                        <span class="image-card-date">${formatDate(img.created)}</span>
                        <div class="image-card-actions">
                            <button class="btn-edit" onclick="app.editImage('${img.id}')">Edit</button>
                            <button class="btn-danger" onclick="app.deleteImage('${img.id}')">Del</button>
                        </div>
                    </div>
                    ${img.tags.length ? `<div class="item-tags">${img.tags.map(t => `<span class="tag">${esc(t)}</span>`).join('')}</div>` : ''}
                </div>
            </div>
        `).join('');

        // Load thumbnails asynchronously
        for (const img of filtered) {
            loadThumbnail(img.id, img.mimeType);
        }
    }

    async function loadThumbnail(id, mimeType) {
        try {
            const stored = await dbGet(id);
            if (!stored) return;
            const blob = await decryptBlob(stored.encrypted, currentPin, mimeType);
            const url = URL.createObjectURL(blob);
            const thumbEl = imagesList.querySelector(`img[data-img-id="${id}"]`);
            if (thumbEl) {
                thumbEl.src = url;
                thumbEl.onload = () => URL.revokeObjectURL(url);
            }
        } catch {
            // silently fail for missing/corrupt blobs
        }
    }

    async function viewImage(id) {
        const img = vaultData.images.find(i => i.id === id);
        if (!img) return;

        try {
            const stored = await dbGet(id);
            if (!stored) return;
            const blob = await decryptBlob(stored.encrypted, currentPin, img.mimeType);
            const url = URL.createObjectURL(blob);
            currentViewerImageId = id;
            viewerTitle.textContent = img.title;
            viewerImg.src = url;
            viewerImg.onload = () => URL.revokeObjectURL(url);
            imageViewer.classList.remove('hidden');
        } catch {
            alert('ERR: FAILED TO DECRYPT IMAGE');
        }
    }

    async function downloadImage() {
        if (!currentViewerImageId) return;
        const img = vaultData.images.find(i => i.id === currentViewerImageId);
        if (!img) return;

        try {
            const stored = await dbGet(currentViewerImageId);
            if (!stored) return;
            const blob = await decryptBlob(stored.encrypted, currentPin, img.mimeType);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            const ext = img.mimeType.split('/')[1] || 'png';
            a.download = `${img.title.replace(/[^a-z0-9]/gi, '_')}.${ext}`;
            a.click();
            URL.revokeObjectURL(url);
        } catch {
            alert('ERR: FAILED TO DOWNLOAD IMAGE');
        }
    }

    function closeViewer() {
        imageViewer.classList.add('hidden');
        viewerImg.src = '';
        currentViewerImageId = null;
    }

    async function deleteImage(id) {
        vaultData.images = vaultData.images.filter(i => i.id !== id);
        await dbDelete(id);
        saveVault();
        renderImages();
    }

    function editImage(id) {
        const img = vaultData.images.find(i => i.id === id);
        if (!img) return;

        modalTitle.textContent = 'EDIT_IMAGE';
        modalFields.innerHTML = `
            <div class="input-group">
                <span class="input-prefix">title:</span>
                <input type="text" id="edit-image-title" class="input-field" value="${esc(img.title)}" placeholder="image title">
            </div>
            <div class="input-group">
                <span class="input-prefix">tags:</span>
                <input type="text" id="edit-image-tags" class="input-field" value="${esc(img.tags.join(', '))}" placeholder="tag1, tag2">
            </div>
        `;
        editModal.classList.remove('hidden');
        editModal.dataset.type = 'image';
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
        } else if (type === 'image') {
            const img = vaultData.images.find(i => i.id === id);
            if (img) {
                img.title = $('edit-image-title').value.trim() || img.title;
                img.tags = $('edit-image-tags').value.split(',').map(t => t.trim()).filter(Boolean);
            }
            renderImages();
        }

        saveVault();
        closeModal();
    }

    // --- Import / Export ---
    async function exportData() {
        // Export vault metadata + encrypted image blobs
        const exportObj = { ...vaultData };

        // Include image blobs from IndexedDB
        if (vaultData.images && vaultData.images.length > 0) {
            exportObj._imageBlobs = {};
            for (const img of vaultData.images) {
                try {
                    const stored = await dbGet(img.id);
                    if (stored) {
                        // Convert encrypted Uint8Arrays to base64 for JSON transport
                        exportObj._imageBlobs[img.id] = {
                            iv: uint8ToBase64(stored.encrypted.iv),
                            data: uint8ToBase64(stored.encrypted.data),
                            mimeType: stored.mimeType
                        };
                    }
                } catch { /* skip missing blobs */ }
            }
        }

        const blob = new Blob([JSON.stringify(exportObj)], { type: 'application/json' });
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
                // Ensure images array exists
                if (!imported.images) imported.images = [];

                // Restore image blobs to IndexedDB
                if (imported._imageBlobs) {
                    for (const [id, blobObj] of Object.entries(imported._imageBlobs)) {
                        const encrypted = {
                            iv: base64ToUint8(blobObj.iv),
                            data: base64ToUint8(blobObj.data)
                        };
                        await dbPut(id, { encrypted, mimeType: blobObj.mimeType });
                    }
                    delete imported._imageBlobs;
                }

                vaultData = imported;
                await saveVault();
                renderLinks();
                renderNotes();
                renderImages();
            }
        } catch {
            alert('ERR: INVALID BACKUP FILE');
        }
        e.target.value = '';
    }

    function uint8ToBase64(arr) {
        return btoa(String.fromCharCode(...arr));
    }

    function base64ToUint8(b64) {
        return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
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

    // --- Chat Integration ---
    let chatInitialized = false;

    async function initChatTab() {
        if (chatInitialized) return;

        try {
            // Dynamically import chat modules
            const { initChat, showAuthScreen, initSearchUI, logoutChat } = await import('./chat/ui.js');

            const loggedIn = await initChat();
            if (!loggedIn) {
                showAuthScreen();
            }

            initSearchUI();

            // Logout handler
            $('btn-chat-logout')?.addEventListener('click', () => {
                logoutChat();
                chatInitialized = false;
            });

            chatInitialized = true;
        } catch (err) {
            console.error('Chat init failed:', err);
            const chatAuth = $('chat-auth');
            if (chatAuth) {
                chatAuth.innerHTML = `<div class="error-text" style="text-align:center;padding:2rem;">Chat initialization failed: ${esc(err.message)}</div>`;
            }
        }
    }

    // Override switchTab to handle chat tab
    const originalSwitchTab = switchTab;
    function switchTabWithChat(tab) {
        document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === `tab-${tab}`));

        if (tab === 'chat') {
            initChatTab();
        }
    }

    // Rebind tab clicks to use new switchTab
    document.querySelectorAll('.tab').forEach(tab => {
        tab.replaceWith(tab.cloneNode(true));
    });
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => switchTabWithChat(tab.dataset.tab));
    });

    // --- Expose for inline onclick ---
    window.app = { editLink, deleteLink, editNote, deleteNote, editImage, deleteImage, viewImage };

    // --- Start ---
    init();
})();
