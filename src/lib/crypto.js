/**
 * KeyGuard Crypto — криптографическое ядро.
 *
 * Схема:
 *   мастер-пароль --PBKDF2-SHA256(310 000 итераций)--> AES-256-GCM ключ
 *   ключ --AES-GCM--> зашифрованный словарь записей (хранится в chrome.storage.local)
 *   ключ --AES-GCM--> verifier (проверка правильности мастер-пароля)
 *
 * Мастер-пароль и ключ никогда не сохраняются в открытом виде на диск.
 * Соль и IV генерируются криптостойким ГСЧ на каждое шифрование.
 */
(() => {
  'use strict';

  const ITERATIONS = 310000;
  const VERIFIER_PLAINTEXT = 'keyguard::vault-verifier::v1';
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  function bytesToBase64(bytes) {
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  function toBase64(buffer) {
    return bytesToBase64(new Uint8Array(buffer));
  }

  function fromBase64(value) {
    return base64ToBytes(value);
  }

  function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  /**
   * Производит ключ AES-256-GCM из мастер-пароля и соли.
   * @param {string} password
   * @param {string} saltBase64
   * @param {number} [iterations]
   * @returns {Promise<CryptoKey>}
   */
  async function deriveKey(password, saltBase64, iterations = ITERATIONS) {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      textEncoder.encode(password.normalize('NFKC')),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: fromBase64(saltBase64),
        iterations,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async function exportKey(key) {
    const raw = await crypto.subtle.exportKey('raw', key);
    return toBase64(raw);
  }

  async function importKey(rawBase64) {
    return crypto.subtle.importKey('raw', fromBase64(rawBase64), { name: 'AES-GCM' }, true, [
      'encrypt',
      'decrypt'
    ]);
  }

  async function encryptString(key, plaintext) {
    const iv = randomBytes(12);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      textEncoder.encode(plaintext)
    );
    return { iv: toBase64(iv), ct: toBase64(ciphertext) };
  }

  async function decryptString(key, payload) {
    if (!payload || !payload.iv || !payload.ct) throw new Error('Повреждённые данные хранилища');
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(payload.iv) },
      key,
      fromBase64(payload.ct)
    );
    return textDecoder.decode(plaintext);
  }

  async function encryptJson(key, value) {
    return encryptString(key, JSON.stringify(value));
  }

  async function decryptJson(key, payload) {
    return JSON.parse(await decryptString(key, payload));
  }

  function emptyVault() {
    return {
      version: 1,
      entries: [],
      createdAt: new Date().toISOString()
    };
  }

  /**
   * Создаёт новое зашифрованное хранилище.
   * @param {string} password мастер-пароль
   * @returns {Promise<{key: CryptoKey, record: object, vault: object}>}
   */
  async function createVault(password) {
    const salt = toBase64(randomBytes(16));
    const key = await deriveKey(password, salt, ITERATIONS);
    const now = new Date().toISOString();
    const vault = emptyVault();
    const verifier = await encryptString(key, VERIFIER_PLAINTEXT);
    const data = await encryptJson(key, vault);
    return {
      key,
      vault,
      record: {
        version: 1,
        iterations: ITERATIONS,
        salt,
        verifier,
        data,
        createdAt: now,
        updatedAt: now
      }
    };
  }

  /**
   * Проверяет мастер-пароль и расшифровывает хранилище.
   * @param {string} password
   * @param {object} record
   * @returns {Promise<{key: CryptoKey, vault: object}>}
   */
  async function unlockVault(password, record) {
    if (!record || !record.salt || !record.verifier || !record.data) {
      throw new Error('Некорректный формат хранилища');
    }
    const iterations = record.iterations || ITERATIONS;
    const key = await deriveKey(password, record.salt, iterations);
    let verifier;
    try {
      verifier = await decryptString(key, record.verifier);
    } catch (error) {
      throw new Error('Неверный мастер-пароль');
    }
    if (!timingSafeEqual(verifier, VERIFIER_PLAINTEXT)) {
      throw new Error('Неверный мастер-пароль');
    }
    const vault = await decryptJson(key, record.data);
    if (!vault || !Array.isArray(vault.entries)) {
      throw new Error('Повреждённые данные хранилища');
    }
    return { key, vault };
  }

  /**
   * Перешифровывает хранилище и возвращает обновлённую запись.
   */
  async function persistVault(key, record, vault) {
    const now = new Date().toISOString();
    const data = await encryptJson(key, vault);
    return {
      ...record,
      data,
      updatedAt: now
    };
  }

  /**
   * Смена мастер-пароля: новый ключ, новая соль, заново шифруются все данные.
   */
  async function rekeyVault(record, vault, newPassword) {
    const salt = toBase64(randomBytes(16));
    const key = await deriveKey(newPassword, salt, ITERATIONS);
    const now = new Date().toISOString();
    const verifier = await encryptString(key, VERIFIER_PLAINTEXT);
    const data = await encryptJson(key, vault);
    return {
      key,
      record: {
        version: 1,
        iterations: ITERATIONS,
        salt,
        verifier,
        data,
        createdAt: record.createdAt || now,
        updatedAt: now
      }
    };
  }

  async function sha1Hex(text) {
    const digest = await crypto.subtle.digest('SHA-1', textEncoder.encode(text));
    return [...new Uint8Array(digest)]
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
  }

  globalThis.KeyGuardCrypto = {
    ITERATIONS,
    VERIFIER_PLAINTEXT,
    deriveKey,
    exportKey,
    importKey,
    encryptString,
    decryptString,
    encryptJson,
    decryptJson,
    createVault,
    unlockVault,
    persistVault,
    rekeyVault,
    sha1Hex,
    randomBytes,
    toBase64,
    fromBase64,
    timingSafeEqual
  };
})();
