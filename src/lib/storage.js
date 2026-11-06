/**
 * KeyGuard Storage — тонкая обёртка над chrome.storage.local / session.
 * В local хранится только зашифрованный конверт, в session — сырой ключ
 * (живёт до перезапуска браузера и стирается при блокировке).
 */
(() => {
  'use strict';

  const LOCAL_KEY = 'keyguard_vault_v1';
  const SESSION_KEY = 'keyguard_session_key_v1';
  const SETTINGS_KEY = 'keyguard_settings_v1';

  const DEFAULT_SETTINGS = {
    autoLockMinutes: 5,
    clipboardClearSeconds: 30,
    lockOnIdle: true,
    breachCheck: true,
    generator: {
      length: 20,
      lower: true,
      upper: true,
      digits: true,
      symbols: true,
      avoidAmbiguous: true
    }
  };

  function hasChromeStorage() {
    return typeof chrome !== 'undefined' && chrome && chrome.storage;
  }

  function localGet(key) {
    return new Promise((resolve) => {
      if (!hasChromeStorage() || !chrome.storage.local) return resolve(undefined);
      chrome.storage.local.get(key, (result) => resolve(result ? result[key] : undefined));
    });
  }

  function localSet(key, value) {
    return new Promise((resolve) => {
      if (!hasChromeStorage() || !chrome.storage.local) return resolve();
      chrome.storage.local.set({ [key]: value }, () => resolve());
    });
  }

  function localRemove(key) {
    return new Promise((resolve) => {
      if (!hasChromeStorage() || !chrome.storage.local) return resolve();
      chrome.storage.local.remove(key, () => resolve());
    });
  }

  function sessionGet(key) {
    return new Promise((resolve) => {
      if (!hasChromeStorage() || !chrome.storage.session) return resolve(undefined);
      chrome.storage.session.get(key, (result) => resolve(result ? result[key] : undefined));
    });
  }

  function sessionSet(key, value) {
    return new Promise((resolve) => {
      if (!hasChromeStorage() || !chrome.storage.session) return resolve();
      chrome.storage.session.set({ [key]: value }, () => resolve());
    });
  }

  function sessionRemove(key) {
    return new Promise((resolve) => {
      if (!hasChromeStorage() || !chrome.storage.session) return resolve();
      chrome.storage.session.remove(key, () => resolve());
    });
  }

  async function getVaultRecord() {
    return (await localGet(LOCAL_KEY)) || null;
  }

  async function setVaultRecord(record) {
    await localSet(LOCAL_KEY, record);
    return record;
  }

  async function vaultExists() {
    return Boolean(await getVaultRecord());
  }

  async function getSessionKey() {
    return (await sessionGet(SESSION_KEY)) || null;
  }

  async function setSessionKey(rawKey) {
    await sessionSet(SESSION_KEY, rawKey);
  }

  async function clearSessionKey() {
    await sessionRemove(SESSION_KEY);
  }

  async function getSettings() {
    const stored = await localGet(SETTINGS_KEY);
    return {
      ...DEFAULT_SETTINGS,
      ...(stored || {}),
      generator: { ...DEFAULT_SETTINGS.generator, ...((stored || {}).generator || {}) }
    };
  }

  async function setSettings(settings) {
    const current = await getSettings();
    const next = {
      ...current,
      ...settings,
      generator: { ...current.generator, ...((settings || {}).generator || {}) }
    };
    await localSet(SETTINGS_KEY, next);
    return next;
  }

  async function resetAll() {
    await localRemove(LOCAL_KEY);
    await localRemove(SETTINGS_KEY);
    await clearSessionKey();
  }

  globalThis.KeyGuardStorage = {
    LOCAL_KEY,
    SESSION_KEY,
    SETTINGS_KEY,
    DEFAULT_SETTINGS,
    getVaultRecord,
    setVaultRecord,
    vaultExists,
    getSessionKey,
    setSessionKey,
    clearSessionKey,
    getSettings,
    setSettings,
    resetAll
  };
})();
