/**
 * KeyGuard Background — service worker (Manifest V3).
 *
 * Здесь живёт расшифрованный ключ (только в памяти + chrome.storage.session),
 * поэтому popup и content script не работают с мастер-паролем напрямую.
 */
importScripts('lib/crypto.js', 'lib/storage.js', 'lib/generator.js', 'lib/totp.js');

const Crypto = globalThis.KeyGuardCrypto;
const Storage = globalThis.KeyGuardStorage;

const AUTOLOCK_ALARM = 'keyguard-autolock';
const CLIPBOARD_ALARM = 'keyguard-clipboard-clear';
const SESSION_CONTEXT_KEY = 'keyguard_clipboard_pending';

let unlockedKey = null;
let vault = null;
let record = null;
let lastActivity = Date.now();
let idleInterval = 30;
let restorePromise = null;

const breachCache = new Map();

/* ------------------------------------------------------------------ */
/* Вспомогательные функции                                             */
/* ------------------------------------------------------------------ */

function touch() {
  lastActivity = Date.now();
}

function nowIso() {
  return new Date().toISOString();
}

function normalizeEntry(entry = {}) {
  const type = ['login', 'card', 'note'].includes(entry.type) ? entry.type : 'login';
  const password = typeof entry.password === 'string' ? entry.password : '';
  return {
    id: entry.id || crypto.randomUUID(),
    type,
    title: String(entry.title || '').trim() || 'Без названия',
    username: entry.username || '',
    password,
    url: entry.url || '',
    notes: entry.notes || '',
    card: {
      number: '',
      holder: '',
      expiry: '',
      cvv: '',
      ...(entry.card || {})
    },
    favorite: Boolean(entry.favorite),
    totp: entry.totp || '',
    createdAt: entry.createdAt || nowIso(),
    updatedAt: nowIso(),
    passwordUpdatedAt: entry.passwordUpdatedAt || (password ? entry.createdAt || nowIso() : null)
  };
}

function sortEntries(entries) {
  return [...entries].sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    return new Date(b.updatedAt) - new Date(a.updatedAt);
  });
}

function findEntry(id) {
  return vault?.entries.find((entry) => entry.id === id) || null;
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch (error) {
    return '';
  }
}

function matchesSite(entry, url) {
  if (!entry.url || !url) return false;
  try {
    const entryHost = new URL(entry.url).hostname.replace(/^www\./, '');
    const pageHost = new URL(url).hostname.replace(/^www\./, '');
    return entryHost === pageHost || pageHost.endsWith(`.${entryHost}`);
  } catch (error) {
    return false;
  }
}

function bestEntryForUrl(url) {
  if (!vault || !url) return null;
  const logins = vault.entries.filter((entry) => entry.type === 'login' && entry.password);
  return (
    logins.find((entry) => matchesSite(entry, url) && entry.username) ||
    logins.find((entry) => matchesSite(entry, url)) ||
    null
  );
}

async function persistVault() {
  if (!unlockedKey || !record || !vault) throw new Error('Хранилище заблокировано');
  record = await Crypto.persistVault(unlockedKey, record, vault);
  await Storage.setVaultRecord(record);
  return record;
}

async function restoreSession() {
  const storedRecord = await Storage.getVaultRecord();
  if (!storedRecord) return false;
  const rawKey = await Storage.getSessionKey();
  if (!rawKey) return false;
  try {
    const key = await Crypto.importKey(rawKey);
    const verifier = await Crypto.decryptString(key, storedRecord.verifier);
    if (verifier !== Crypto.VERIFIER_PLAINTEXT) throw new Error('bad verifier');
    const data = await Crypto.decryptJson(key, storedRecord.data);
    if (!data || !Array.isArray(data.entries)) throw new Error('bad data');
    unlockedKey = key;
    vault = data;
    record = storedRecord;
    return true;
  } catch (error) {
    await Storage.clearSessionKey();
    return false;
  }
}

function ensureSession() {
  if (!restorePromise) {
    restorePromise = restoreSession().catch(() => false);
  }
  return restorePromise;
}

async function lock(reason = 'manual') {
  const wasLocked = Boolean(unlockedKey);
  unlockedKey = null;
  vault = null;
  lastActivity = 0;
  await Storage.clearSessionKey();
  if (wasLocked) {
    await broadcast({ type: 'KEYGUARD_LOCKED', reason });
  }
}

async function broadcast(message) {
  try {
    await chrome.runtime.sendMessage(message);
  } catch (error) {
    /* нет открытых страниц — это нормально */
  }
}

async function getState() {
  const exists = record ? true : await Storage.vaultExists();
  return {
    hasVault: exists,
    unlocked: Boolean(unlockedKey),
    settings: await Storage.getSettings()
  };
}

function requireUnlocked() {
  if (!unlockedKey || !vault) throw new Error('Хранилище заблокировано');
}

async function sendToTab(tabId, message) {
  try {
    return await chrome.tabs.sendMessage(tabId, message);
  } catch (error) {
    await chrome.scripting.executeScript({ target: { tabId }, files: ['src/content.js'] });
    return chrome.tabs.sendMessage(tabId, message);
  }
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

/* ------------------------------------------------------------------ */
/* Проверка утечек (HIBP, k-anonymity)                                 */
/* ------------------------------------------------------------------ */

async function checkBreach(password) {
  const hash = await Crypto.sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  if (!breachCache.has(prefix)) {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' }
    });
    if (!response.ok) throw new Error('Сервис проверки утечек недоступен');
    const text = await response.text();
    const map = new Map();
    for (const line of text.split('\n')) {
      const [lineSuffix, count] = line.trim().split(':');
      if (lineSuffix && count) map.set(lineSuffix, Number(count));
    }
    breachCache.set(prefix, map);
  }
  const count = breachCache.get(prefix).get(suffix) || 0;
  return { breached: count > 0, count };
}

/* ------------------------------------------------------------------ */
/* Буфер обмена                                                        */
/* ------------------------------------------------------------------ */

async function scheduleClipboardClear(seconds) {
  const delay = Math.max(5, Number(seconds) || 30);
  try {
    await chrome.storage.session.set({ [SESSION_CONTEXT_KEY]: Date.now() + delay * 1000 });
  } catch (error) {
    /* session storage может быть недоступен */
  }
  await chrome.alarms.clear(CLIPBOARD_ALARM);
  chrome.alarms.create(CLIPBOARD_ALARM, { when: Date.now() + delay * 1000 });
}

async function clearClipboard() {
  try {
    const tab = await getActiveTab();
    if (tab && tab.id) {
      await sendToTab(tab.id, { type: 'KEYGUARD_CLEAR_CLIPBOARD' });
    }
  } catch (error) {
    /* страница может не поддерживать clipboard API */
  }
}

/* ------------------------------------------------------------------ */
/* Автоблокировка                                                      */
/* ------------------------------------------------------------------ */

async function applyIdleSettings() {
  const settings = await Storage.getSettings();
  const seconds = Math.min(300, Math.max(15, Math.round(settings.autoLockMinutes * 60)));
  if (seconds !== idleInterval) {
    idleInterval = seconds;
    try {
      chrome.idle.setDetectionInterval(idleInterval);
    } catch (error) {
      /* ignore */
    }
  }
}

async function setupAlarms() {
  await applyIdleSettings();
  chrome.alarms.create(AUTOLOCK_ALARM, { periodInMinutes: 0.5 });
}

/* ------------------------------------------------------------------ */
/* Контекстное меню                                                    */
/* ------------------------------------------------------------------ */

function setupContextMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: 'keyguard-fill',
      title: 'Заполнить паролем из KeyGuard',
      contexts: ['editable', 'page']
    });
    chrome.contextMenus.create({
      id: 'keyguard-options',
      title: 'Настройки KeyGuard',
      contexts: ['action']
    });
  });
}

async function handleContextMenu(info, tab) {
  if (!tab || !tab.id) return;
  if (info.menuItemId === 'keyguard-options') {
    chrome.runtime.openOptionsPage();
    return;
  }
  if (info.menuItemId !== 'keyguard-fill') return;
  if (!unlockedKey) {
    await sendToTab(tab.id, { type: 'KEYGUARD_TOAST', text: 'Сначала разблокируйте KeyGuard' });
    return;
  }
  const entry = bestEntryForUrl(info.pageUrl || tab.url);
  if (!entry) {
    await sendToTab(tab.id, {
      type: 'KEYGUARD_TOAST',
      text: 'В хранилище нет пароля для этого сайта'
    });
    return;
  }
  touch();
  await sendToTab(tab.id, { type: 'KEYGUARD_FILL', entry });
}

/* ------------------------------------------------------------------ */
/* Маршрутизация сообщений                                             */
/* ------------------------------------------------------------------ */

async function handleMessage(message, sender) {
  await ensureSession();
  const type = message?.type;
  const tabId = sender?.tab?.id;

  switch (type) {
    case 'PING': {
      if (message.touch) touch();
      return { ok: true, state: await getState() };
    }
    case 'GET_STATE': {
      return { ok: true, ...(await getState()) };
    }
    case 'CREATE_VAULT': {
      const password = String(message.password || '');
      if (password.length < 8) throw new Error('Мастер-пароль должен быть не короче 8 символов');
      if (await Storage.vaultExists()) throw new Error('Хранилище уже создано');
      const created = await Crypto.createVault(password);
      unlockedKey = created.key;
      vault = created.vault;
      record = created.record;
      await Storage.setVaultRecord(record);
      await Storage.setSessionKey(await Crypto.exportKey(unlockedKey));
      touch();
      await broadcast({ type: 'KEYGUARD_UNLOCKED' });
      return { ok: true, state: await getState() };
    }
    case 'UNLOCK': {
      const storedRecord = await Storage.getVaultRecord();
      if (!storedRecord) throw new Error('Хранилище не найдено');
      const opened = await Crypto.unlockVault(String(message.password || ''), storedRecord);
      unlockedKey = opened.key;
      vault = opened.vault;
      record = storedRecord;
      await Storage.setSessionKey(await Crypto.exportKey(unlockedKey));
      touch();
      await broadcast({ type: 'KEYGUARD_UNLOCKED' });
      return { ok: true, state: await getState() };
    }
    case 'LOCK': {
      await lock('manual');
      return { ok: true, state: await getState() };
    }
    case 'GET_ENTRIES': {
      requireUnlocked();
      touch();
      return { ok: true, entries: sortEntries(vault.entries) };
    }
    case 'UPSERT_ENTRY': {
      requireUnlocked();
      const incoming = normalizeEntry(message.entry);
      const index = vault.entries.findIndex((entry) => entry.id === incoming.id);
      if (index >= 0) {
        const previous = vault.entries[index];
        incoming.createdAt = previous.createdAt;
        if (previous.password !== incoming.password) incoming.passwordUpdatedAt = nowIso();
        else incoming.passwordUpdatedAt = previous.passwordUpdatedAt;
        vault.entries[index] = incoming;
      } else {
        vault.entries.unshift(incoming);
      }
      await persistVault();
      touch();
      return { ok: true, entries: sortEntries(vault.entries), entry: incoming };
    }
    case 'DELETE_ENTRY': {
      requireUnlocked();
      vault.entries = vault.entries.filter((entry) => entry.id !== message.id);
      await persistVault();
      touch();
      return { ok: true, entries: sortEntries(vault.entries) };
    }
    case 'TOGGLE_FAVORITE': {
      requireUnlocked();
      const entry = findEntry(message.id);
      if (!entry) throw new Error('Запись не найдена');
      entry.favorite = !entry.favorite;
      entry.updatedAt = nowIso();
      await persistVault();
      touch();
      return { ok: true, entries: sortEntries(vault.entries) };
    }
    case 'CHANGE_MASTER_PASSWORD': {
      requireUnlocked();
      const currentPassword = String(message.currentPassword || '');
      const newPassword = String(message.newPassword || '');
      if (newPassword.length < 8) throw new Error('Новый пароль должен быть не короче 8 символов');
      const storedRecord = await Storage.getVaultRecord();
      const opened = await Crypto.unlockVault(currentPassword, storedRecord);
      const rekeyed = await Crypto.rekeyVault(storedRecord, vault, newPassword);
      unlockedKey = rekeyed.key;
      record = rekeyed.record;
      await Storage.setVaultRecord(record);
      await Storage.setSessionKey(await Crypto.exportKey(unlockedKey));
      touch();
      return { ok: true, state: await getState() };
    }
    case 'GET_SETTINGS': {
      return { ok: true, settings: await Storage.getSettings() };
    }
    case 'SET_SETTINGS': {
      const settings = await Storage.setSettings(message.settings || {});
      await applyIdleSettings();
      return { ok: true, settings };
    }
    case 'EXPORT_BACKUP': {
      requireUnlocked();
      const storedRecord = await Storage.getVaultRecord();
      return {
        ok: true,
        record: {
          app: 'KeyGuard',
          kind: 'encrypted-backup',
          version: 1,
          exportedAt: nowIso(),
          vault: storedRecord
        }
      };
    }
    case 'IMPORT_BACKUP': {
      const backup = message.record?.vault || message.record;
      if (!backup || !backup.salt || !backup.verifier || !backup.data) {
        throw new Error('Это не резервная копия KeyGuard');
      }
      const opened = await Crypto.unlockVault(String(message.password || ''), backup);
      unlockedKey = opened.key;
      vault = opened.vault;
      record = backup;
      await Storage.setVaultRecord(record);
      await Storage.setSessionKey(await Crypto.exportKey(unlockedKey));
      touch();
      await broadcast({ type: 'KEYGUARD_UNLOCKED' });
      return { ok: true, state: await getState() };
    }
    case 'RESET_VAULT': {
      unlockedKey = null;
      vault = null;
      record = null;
      await Storage.resetAll();
      return { ok: true, state: await getState() };
    }
    case 'CHECK_BREACH': {
      const password = String(message.password || '');
      if (!password) throw new Error('Пароль не задан');
      return { ok: true, ...(await checkBreach(password)) };
    }
    case 'GET_PAGE_FORM': {
      const tab = tabId ? { id: tabId } : await getActiveTab();
      if (!tab?.id) throw new Error('Не удалось определить вкладку');
      const form = await sendToTab(tab.id, { type: 'KEYGUARD_GET_FORM' });
      return { ok: true, form };
    }
    case 'FILL_ON_PAGE': {
      requireUnlocked();
      const tab = tabId ? { id: tabId } : await getActiveTab();
      if (!tab?.id) throw new Error('Не удалось определить вкладку');
      const entry = message.entryId ? findEntry(message.entryId) : bestEntryForUrl(message.url || tab.url);
      if (!entry) throw new Error('Нет подходящей записи');
      touch();
      const result = await sendToTab(tab.id, { type: 'KEYGUARD_FILL', entry });
      return { ok: true, ...result };
    }
    case 'SCHEDULE_CLIPBOARD_CLEAR': {
      await scheduleClipboardClear(message.seconds);
      return { ok: true };
    }
    case 'KEYGUARD_SUBMITTED': {
      if (!unlockedKey) return { ok: true, prompt: null };
      const { origin, title, username, password } = message.credentials || {};
      if (!origin || !password) return { ok: true, prompt: null };
      const existing = vault.entries.find(
        (entry) =>
          entry.type === 'login' &&
          entry.username &&
          username &&
          entry.username.toLowerCase() === String(username).toLowerCase() &&
          matchesSite(entry, origin)
      );
      if (existing && existing.password === password) return { ok: true, prompt: null };
      if (existing) {
        return {
          ok: true,
          prompt: {
            mode: 'update',
            entry: {
              id: existing.id,
              title: existing.title,
              username: existing.username,
              origin
            }
          }
        };
      }
      return {
        ok: true,
        prompt: {
          mode: 'save',
          entry: {
            title: title || hostFromUrl(origin) || 'Новый пароль',
            username: username || '',
            origin
          }
        }
      };
    }
    case 'KEYGUARD_PROMPT_ACTION': {
      requireUnlocked();
      const { action, credentials, existingId } = message;
      if (action === 'dismiss') return { ok: true };
      if (!credentials?.password) return { ok: true };
      const existing = existingId ? findEntry(existingId) : null;
      if (existing) {
        existing.password = credentials.password;
        existing.passwordUpdatedAt = nowIso();
        existing.updatedAt = nowIso();
        if (credentials.username) existing.username = credentials.username;
      } else {
        vault.entries.unshift(
          normalizeEntry({
            type: 'login',
            title: credentials.title || hostFromUrl(credentials.origin) || 'Новый пароль',
            username: credentials.username || '',
            password: credentials.password,
            url: credentials.origin || '',
            notes: ''
          })
        );
      }
      await persistVault();
      touch();
      return { ok: true, entries: sortEntries(vault.entries) };
    }
    default:
      throw new Error(`Неизвестная команда: ${type}`);
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then((response) => sendResponse(response))
    .catch((error) => sendResponse({ ok: false, error: error?.message || 'Внутренняя ошибка' }));
  return true;
});

/* ------------------------------------------------------------------ */
/* События жизненного цикла                                            */
/* ------------------------------------------------------------------ */

chrome.runtime.onInstalled.addListener(async () => {
  setupContextMenus();
  await setupAlarms();
  await ensureSession();
});

chrome.runtime.onStartup.addListener(async () => {
  setupContextMenus();
  await setupAlarms();
  await ensureSession();
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === AUTOLOCK_ALARM) {
    const settings = await Storage.getSettings();
    if (unlockedKey && Date.now() - lastActivity > settings.autoLockMinutes * 60000) {
      await lock('timeout');
    }
    return;
  }
  if (alarm.name === CLIPBOARD_ALARM) {
    await clearClipboard();
    try {
      await chrome.storage.session.remove(SESSION_CONTEXT_KEY);
    } catch (error) {
      /* ignore */
    }
  }
});

chrome.idle.onStateChanged.addListener(async (state) => {
  if (state === 'active') return;
  const settings = await Storage.getSettings();
  if (settings.lockOnIdle && unlockedKey) await lock('idle');
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  handleContextMenu(info, tab).catch(() => {});
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.keyguard_settings_v1) {
    applyIdleSettings().catch(() => {});
  }
});

/* Инициализация при каждом запуске service worker (в том числе после
   перезапуска), чтобы контекстное меню, таймеры и ключ были на месте. */
setupContextMenus();
setupAlarms().catch(() => {});
ensureSession();
