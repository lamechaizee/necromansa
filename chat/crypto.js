// NECROMANSA E2E Encryption Module
// Uses libsodium for X25519 ECDH + XChaCha20-Poly1305

let sodium = null;

export async function initCrypto() {
  if (sodium) return;
  // Load libsodium from CDN
  if (!window.sodium) {
    await new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'https://cdn.jsdelivr.net/npm/libsodium-wrappers@0.7.14/dist/browsers-sumo/sodium.js';
      script.onload = resolve;
      script.onerror = reject;
      document.head.appendChild(script);
    });
  }
  await window.sodium.ready;
  sodium = window.sodium;
}

function ensureSodium() {
  if (!sodium) throw new Error('Crypto not initialized. Call initCrypto() first.');
}

// Generate signing keypair (Ed25519)
export function generateSigningKeypair() {
  ensureSodium();
  const kp = sodium.crypto_sign_keypair();
  return {
    publicKey: sodium.to_base64(kp.publicKey),
    privateKey: sodium.to_base64(kp.privateKey)
  };
}

// Generate encryption keypair (X25519)
export function generateEncryptionKeypair() {
  ensureSodium();
  const kp = sodium.crypto_box_keypair();
  return {
    publicKey: sodium.to_base64(kp.publicKey),
    privateKey: sodium.to_base64(kp.privateKey)
  };
}

// Derive encryption key from PIN for protecting private keys
export async function deriveKeyFromPin(pin) {
  ensureSodium();
  const salt = sodium.from_string('necromansa_vault_2026');
  const key = sodium.crypto_pwhash(
    sodium.crypto_secretbox_KEYBYTES,
    pin,
    salt,
    sodium.crypto_pwhash_OPSLIMIT_MODERATE,
    sodium.crypto_pwhash_MEMLIMIT_MODERATE,
    sodium.crypto_pwhash_ALG_DEFAULT
  );
  return key;
}

// Encrypt private key with PIN
export async function encryptPrivateKey(privateKeyB64, pin) {
  ensureSodium();
  const key = await deriveKeyFromPin(pin);
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const plaintext = sodium.from_base64(privateKeyB64);
  const ciphertext = sodium.crypto_secretbox_easy(plaintext, nonce, key);
  return {
    nonce: sodium.to_base64(nonce),
    ciphertext: sodium.to_base64(ciphertext)
  };
}

// Decrypt private key with PIN
export async function decryptPrivateKey(encryptedObj, pin) {
  ensureSodium();
  const key = await deriveKeyFromPin(pin);
  const nonce = sodium.from_base64(encryptedObj.nonce);
  const ciphertext = sodium.from_base64(encryptedObj.ciphertext);
  const plaintext = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
  return sodium.to_base64(plaintext);
}

// Encrypt a message for a recipient
export function encryptMessage(plaintext, recipientEncPubKeyB64, senderSignPrivKeyB64) {
  ensureSodium();

  const recipientPubKey = sodium.from_base64(recipientEncPubKeyB64);
  const senderPrivKey = sodium.from_base64(senderSignPrivKeyB64);

  // Generate ephemeral keypair for forward secrecy
  const ephemeralKp = sodium.crypto_box_keypair();

  // Compute shared secret via X25519
  const sharedSecret = sodium.crypto_box_beforenm(recipientPubKey, ephemeralKp.privateKey);

  // Derive symmetric key with HKDF-like construction
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  // Encrypt with XChaCha20-Poly1305
  const messageBytes = sodium.from_string(plaintext);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    messageBytes,
    null,
    null,
    nonce,
    sharedSecret
  );

  // Sign the ciphertext with sender's signing key
  const toSign = new Uint8Array(nonce.length + ephemeralKp.publicKey.length + ciphertext.length);
  toSign.set(nonce, 0);
  toSign.set(ephemeralKp.publicKey, nonce.length);
  toSign.set(ciphertext, nonce.length + ephemeralKp.publicKey.length);

  const signature = sodium.crypto_sign_detached(toSign, senderPrivKey);

  return {
    ciphertext: sodium.to_base64(ciphertext),
    nonce: sodium.to_base64(nonce),
    ephemeralPub: sodium.to_base64(ephemeralKp.publicKey),
    signature: sodium.to_base64(signature)
  };
}

// Decrypt a message from a sender
export function decryptMessage(encryptedData, senderSignPubKeyB64, recipientEncPrivKeyB64) {
  ensureSodium();

  const { ciphertext: ctB64, nonce: nB64, ephemeralPub: epB64, signature: sigB64 } = encryptedData;

  const ciphertext = sodium.from_base64(ctB64);
  const nonce = sodium.from_base64(nB64);
  const ephemeralPub = sodium.from_base64(epB64);
  const signature = sodium.from_base64(sigB64);
  const senderPubKey = sodium.from_base64(senderSignPubKeyB64);
  const recipientPrivKey = sodium.from_base64(recipientEncPrivKeyB64);

  // Verify signature
  const toVerify = new Uint8Array(nonce.length + ephemeralPub.length + ciphertext.length);
  toVerify.set(nonce, 0);
  toVerify.set(ephemeralPub, nonce.length);
  toVerify.set(ciphertext, nonce.length + ephemeralPub.length);

  const valid = sodium.crypto_sign_verify_detached(signature, toVerify, senderPubKey);
  if (!valid) throw new Error('Invalid message signature');

  // Compute shared secret
  const sharedSecret = sodium.crypto_box_beforenm(ephemeralPub, recipientPrivKey);

  // Decrypt
  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    null,
    nonce,
    sharedSecret
  );

  return sodium.to_string(plaintext);
}

// Encrypt image blob for sending
export function encryptBlob(arrayBuffer, recipientEncPubKeyB64, senderSignPrivKeyB64) {
  ensureSodium();

  const recipientPubKey = sodium.from_base64(recipientEncPubKeyB64);
  const senderPrivKey = sodium.from_base64(senderSignPrivKeyB64);

  const ephemeralKp = sodium.crypto_box_keypair();
  const sharedSecret = sodium.crypto_box_beforenm(recipientPubKey, ephemeralKp.privateKey);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  const data = new Uint8Array(arrayBuffer);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    data,
    null,
    null,
    nonce,
    sharedSecret
  );

  const toSign = new Uint8Array(nonce.length + ephemeralKp.publicKey.length + ciphertext.length);
  toSign.set(nonce, 0);
  toSign.set(ephemeralKp.publicKey, nonce.length);
  toSign.set(ciphertext, nonce.length + ephemeralKp.publicKey.length);

  const signature = sodium.crypto_sign_detached(toSign, senderPrivKey);

  return {
    ciphertext: sodium.to_base64(ciphertext),
    nonce: sodium.to_base64(nonce),
    ephemeralPub: sodium.to_base64(ephemeralKp.publicKey),
    signature: sodium.to_base64(signature)
  };
}

// Decrypt image blob
export function decryptBlob(encryptedData, senderSignPubKeyB64, recipientEncPrivKeyB64) {
  ensureSodium();

  const { ciphertext: ctB64, nonce: nB64, ephemeralPub: epB64, signature: sigB64 } = encryptedData;

  const ciphertext = sodium.from_base64(ctB64);
  const nonce = sodium.from_base64(nB64);
  const ephemeralPub = sodium.from_base64(epB64);
  const signature = sodium.from_base64(sigB64);
  const senderPubKey = sodium.from_base64(senderSignPubKeyB64);
  const recipientPrivKey = sodium.from_base64(recipientEncPrivKeyB64);

  const toVerify = new Uint8Array(nonce.length + ephemeralPub.length + ciphertext.length);
  toVerify.set(nonce, 0);
  toVerify.set(ephemeralPub, nonce.length);
  toVerify.set(ciphertext, nonce.length + ephemeralPub.length);

  const valid = sodium.crypto_sign_verify_detached(signature, toVerify, senderPubKey);
  if (!valid) throw new Error('Invalid blob signature');

  const sharedSecret = sodium.crypto_box_beforenm(ephemeralPub, recipientPrivKey);

  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    null,
    nonce,
    sharedSecret
  );

  return plaintext;
}
