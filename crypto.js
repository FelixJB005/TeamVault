// TeamVault encryption (runs in the browser, uses the built-in Web Crypto API).
//
// How it fits together:
//  - Every user has an RSA key pair. The public key is stored on the server.
//    The private key is stored on the server too, but locked with a key made from the user's password.
//  - Every channel (General or a team) has one random AES key. It encrypts the channel's messages and files.
//  - The AES key is stored on the server once per reader, locked with that reader's public key.
//  - The server never sees a password, a private key, an AES key, a message or a file in readable form.

const TVCrypto = (() => {
  const subtle = globalThis.crypto.subtle;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const ITERATIONS = 250000;                       // makes password guessing slow
  const RSA = { name: 'RSA-OAEP', hash: 'SHA-256' };

  /* ---------- Text <-> base64 ---------- */

  function toB64(buffer) {
    const bytes = new Uint8Array(buffer);
    let text = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return btoa(text);
  }

  function fromB64(text) {
    const raw = atob(text);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes;
  }

  /* ---------- Password: login secret and private key lock ---------- */

  function passwordKey(password) {
    return subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
  }

  // What we send to the server instead of the password.
  async function loginSecret(username, password) {
    const salt = encoder.encode('teamvault-login:' + username.trim().toLowerCase());
    const bits = await subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
      await passwordKey(password),
      256
    );
    return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  // A different key from the same password, used only to lock the private key.
  async function lockKey(password, salt) {
    return subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
      await passwordKey(password),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // At registration: make a key pair. Returns texts that are safe to send to the server.
  async function createAccountKeys(password) {
    const pair = await subtle.generateKey(
      { ...RSA, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
      true,
      ['encrypt', 'decrypt']
    );
    const publicJwk = await subtle.exportKey('jwk', pair.publicKey);
    const privateJwk = await subtle.exportKey('jwk', pair.privateKey);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const locked = await subtle.encrypt(
      { name: 'AES-GCM', iv },
      await lockKey(password, salt),
      encoder.encode(JSON.stringify(privateJwk))
    );
    return {
      publicKey: JSON.stringify(publicJwk),
      wrappedPrivateKey: JSON.stringify({ salt: toB64(salt), iv: toB64(iv), data: toB64(locked) }),
    };
  }

  // At sign in: unlock the private key. Throws if the password is wrong.
  async function unlockPrivateKey(wrappedText, password) {
    const wrapped = JSON.parse(wrappedText);
    const plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(wrapped.iv) },
      await lockKey(password, fromB64(wrapped.salt)),
      fromB64(wrapped.data)
    );
    return decoder.decode(plain);   // the private key as JWK text
  }

  const importPrivateKey = (jwkText) => subtle.importKey('jwk', JSON.parse(jwkText), RSA, false, ['decrypt']);
  const importPublicKey = (jwkText) => subtle.importKey('jwk', JSON.parse(jwkText), RSA, false, ['encrypt']);

  /* ---------- Channel keys ---------- */

  const newChannelKey = () => subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

  // Lock a channel key for one person, using their public key (JWK text)
  async function wrapKey(channelKey, publicJwkText) {
    const raw = await subtle.exportKey('raw', channelKey);
    const locked = await subtle.encrypt({ name: 'RSA-OAEP' }, await importPublicKey(publicJwkText), raw);
    return toB64(locked);
  }

  // Unlock a channel key with your own private key
  async function unwrapKey(wrappedB64, privateKey) {
    const raw = await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, fromB64(wrappedB64));
    return subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  }

  /* ---------- Encrypting messages and files with a channel key ---------- */

  async function encryptText(key, text) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(text));
    return { iv: toB64(iv), ct: toB64(data) };
  }

  async function decryptText(key, ivB64, ctB64) {
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) }, key, fromB64(ctB64));
    return decoder.decode(plain);
  }

  // Files are encrypted in chunks (4 MB each), so even a 100 MB file does not need huge buffers.
  // Every chunk has its own IV (a random part plus the chunk number) and the last chunk is marked,
  // so chunks cannot be reordered, removed or cut off without the decryption failing.
  const CHUNK_SIZE = 4 * 1024 * 1024;

  function chunkIv(base, index) {
    const iv = new Uint8Array(12);
    iv.set(base, 0);
    new DataView(iv.buffer).setUint32(8, index);
    return iv;
  }

  // file: a File or Blob. Returns the IV text and a Blob with the encrypted data.
  async function encryptFile(key, file, chunkSize = CHUNK_SIZE) {
    const base = crypto.getRandomValues(new Uint8Array(8));
    const total = Math.max(1, Math.ceil(file.size / chunkSize));
    const parts = [];
    for (let i = 0; i < total; i++) {
      const plain = await file.slice(i * chunkSize, (i + 1) * chunkSize).arrayBuffer();
      const last = new Uint8Array([i === total - 1 ? 1 : 0]);
      parts.push(await subtle.encrypt({ name: 'AES-GCM', iv: chunkIv(base, i), additionalData: last }, key, plain));
    }
    return { iv: toB64(base), blob: new Blob(parts) };
  }

  // buffer: the encrypted data as an ArrayBuffer. Returns a Blob with the original file. Throws if anything was changed.
  async function decryptFile(key, ivB64, buffer, chunkSize = CHUNK_SIZE) {
    const base = fromB64(ivB64);
    const step = chunkSize + 16;                       // each chunk has a 16 byte check value
    const total = Math.max(1, Math.ceil(buffer.byteLength / step));
    const parts = [];
    for (let i = 0; i < total; i++) {
      const piece = buffer.slice(i * step, (i + 1) * step);
      const last = new Uint8Array([i === total - 1 ? 1 : 0]);
      parts.push(await subtle.decrypt({ name: 'AES-GCM', iv: chunkIv(base, i), additionalData: last }, key, piece));
    }
    return new Blob(parts);
  }

  return {
    loginSecret, createAccountKeys, unlockPrivateKey, importPrivateKey,
    newChannelKey, wrapKey, unwrapKey,
    encryptText, decryptText, encryptFile, decryptFile,
  };
})();

// Lets the test script load this file in Node
if (typeof module !== 'undefined' && module.exports) module.exports = TVCrypto;
