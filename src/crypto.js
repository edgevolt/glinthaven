/**
 * Cryptographic Engine
 * Wraps the Web Crypto API to securely derive an AES-GCM key
 * and encrypt/decrypt JSON payloads at rest.
 */

const ITERATIONS = 100000;
const KEY_LEN = 256;
const ALGO_NAME = 'AES-GCM';

const enc = new TextEncoder();
const dec = new TextDecoder();

function buf2b64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function b642buf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: ALGO_NAME, length: KEY_LEN },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a plaintext string (JSON).
 * @param {string} plaintext - The data to encrypt
 * @param {string} password - The master password
 * @returns {Promise<{salt: string, iv: string, ciphertext: string}>}
 */
export async function encryptVault(plaintext, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  const encryptedBuf = await crypto.subtle.encrypt(
    { name: ALGO_NAME, iv },
    key,
    enc.encode(plaintext)
  );

  return {
    salt: buf2b64(salt),
    iv: buf2b64(iv),
    ciphertext: buf2b64(encryptedBuf)
  };
}

/**
 * Decrypts a vault object payload.
 * @param {Object} vaultData - Payload containing { salt, iv, ciphertext }
 * @param {string} password - The master password
 * @returns {Promise<string>} Plaintext JSON
 * @throws Will throw if password is wrong or payload is corrupted.
 */
export async function decryptVault(vaultData, password) {
  const salt = b642buf(vaultData.salt);
  const iv = b642buf(vaultData.iv);
  const ciphertext = b642buf(vaultData.ciphertext);

  const key = await deriveKey(password, salt);

  try {
    const decryptedBuf = await crypto.subtle.decrypt(
      { name: ALGO_NAME, iv },
      key,
      ciphertext
    );
    return dec.decode(decryptedBuf);
  } catch (err) {
    throw new Error('Invalid password or corrupted vault');
  }
}
