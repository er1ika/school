/**
 * KeyGuard Background — service worker (Manifest V3).
 *
 * Здесь живёт расшифрованный ключ (только в памяти + chrome.storage.session),
 * поэтому popup и content script не работают с мастер-паролем напрямую.
 */

/* =====================================================================
   КАК ЧИТАТЬ ЭТОТ ФАЙЛ
   ---------------------------------------------------------------------
   background.js — это «мозг» расширения. Он работает в фоне, даже когда
   попап закрыт. Здесь хранится расшифрованный ключ и сами записи.

   1. Импорт модулей и состояние.
   2. Вспомогательные функции (нормализация записей, поиск по сайту).
   3. Открытие/блокировка хранилища и восстановление ключа.
   4. Проверка утечек, буфер обмена, автоблокировка.
   5. Контекстное меню.
   6. Маршрутизация сообщений: сюда приходят команды от popup/options/content.
   7. События жизненного цикла Chrome.

   ВАЖНО: master-пароль здесь не хранится. Хранится только CryptoKey,
   полученный из пароля. При блокировке он стирается.
   ===================================================================== */

importScripts('lib/crypto.js', 'lib/storage.js', 'lib/generator.js', 'lib/totp.js');

/* --- 1. Подключение модулей и состояние ---------------------------- */

// Эти объекты появились после importScripts выше.
const Crypto = globalThis.KeyGuardCrypto;
const Storage = globalThis.KeyGuardStorage;  // обёртка над chrome.storage

const AUTOLOCK_ALARM = 'keyguard-autolock';
const CLIPBOARD_ALARM = 'keyguard-clipboard-clear';
const SESSION_CONTEXT_KEY = 'keyguard_clipboard_pending';

// unlockedKey — CryptoKey в памяти. null означает «заблокировано».
// vault — расшифрованный объект с записями.
// record — зашифрованный конверт, который лежит в chrome.storage.local.
let unlockedKey = null;
let vault = null;
let record = null;
let lastActivity = Date.now();  // когда пользователь последний раз что-то делал
let idleInterval = 30;  // интервал проверки простоя (секунды)
let restorePromise = null;  // чтобы не восстанавливать ключ дважды одновременно

const breachCache = new Map();

/* ------------------------------------------------------------------ */
/* 2. Вспомогательные функции                                          */
/* ------------------------------------------------------------------ */

// Отмечаем активность. По этому времени работает автоблокировка.
function touch() {
  lastActivity = Date.now();
}

// Текущее время в формате ISO — так удобно хранить даты в JSON.
function nowIso() {
  return new Date().toISOString();
}

// Приводим запись к единому виду. Это защита от «кривых» данных:
// у каждой записи всегда есть id, type, title, card и даты.
function normalizeEntry(entry = {}) {
  const type = ['login', 'card', 'note'].includes(entry.type) ? entry.type : 'login';
  const password = typeof entry.password === 'string' ? entry.password : '';
  return {
    id: entry.id || crypto.randomUUID(),
    type,
    title: String(entry.title || '').trim() || 'Без названия',
    username: entry.username || '',
    password,  // пароль может быть пустым у карты или заметки
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

// Сначала избранные, потом по дате изменения.
function sortEntries(entries) {
  return [...entries].sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    return new Date(b.updatedAt) - new Date(a.updatedAt);
  });
}

// Найти запись по id в текущем хранилище.
function findEntry(id) {
  return vault?.entries.find((entry) => entry.id === id) || null;
}

// Из URL достаём только домен: https://www.example.com/login → example.com.
function hostFromUrl(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch (error) {
    return '';
  }
}

// Подходит ли запись к сайту. Сравниваем домены и разрешаем поддомены:
// запись для example.com подойдёт для login.example.com.
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

// Выбираем лучшую запись для текущего сайта: сначала с логином, потом любую.
function bestEntryForUrl(url) {
  if (!vault || !url) return null;
  const logins = vault.entries.filter((entry) => entry.type === 'login' && entry.password);
  return (
    logins.find((entry) => matchesSite(entry, url) && entry.username) ||
    logins.find((entry) => matchesSite(entry, url)) ||
    null
  );
}

// Сохранить изменения: заново зашифровать vault и записать конверт в storage.
// Вызывается после каждого добавления/изменения/удаления записи.
async function persistVault() {
  if (!unlockedKey || !record || !vault) throw new Error('Хранилище заблокировано');
  record = await Crypto.persistVault(unlockedKey, record, vault);
  await Storage.setVaultRecord(record);
  return record;
}

// Chrome может «усыпить» service worker и запустить его снова.
// Тогда ключ из памяти пропадёт. restoreSession пробует достать ключ
// из chrome.storage.session и расшифровать им данные.
// Если не получилось — хранилище остаётся заблокированным.
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

// Восстанавливаем сессию один раз. Все сообщения сначала ждут этот Promise,
// чтобы не работать с пустым ключом.
function ensureSession() {
  if (!restorePromise) {
    restorePromise = restoreSession().catch(() => false);
  }
  return restorePromise;
}

// Блокировка: стираем ключ и данные из памяти, чистим session storage.
// После этого для доступа снова нужен мастер-пароль.
// reason нужен для отладки: manual / timeout / idle.
async function lock(reason = 'manual') {
  const wasLocked = Boolean(unlockedKey);
  unlockedKey = null;
  vault = null;
  lastActivity = 0;  // сбрасываем таймер активности
  await Storage.clearSessionKey();
  if (wasLocked) {
    await broadcast({ type: 'KEYGUARD_LOCKED', reason });
  }
}

// Отправляем событие всем открытым страницам расширения (popup, options).
// Если страниц нет, Chrome вернёт ошибку — это нормально, её игнорируем.
async function broadcast(message) {
  try {
    await chrome.runtime.sendMessage(message);
  } catch (error) {
    /* нет открытых страниц — это нормально */
  }
}

// Состояние для интерфейса: есть ли хранилище, разблокировано ли, настройки.
async function getState() {
  const exists = record ? true : await Storage.vaultExists();
  return {
    hasVault: exists,
    unlocked: Boolean(unlockedKey),
    settings: await Storage.getSettings()
  };
}

// Проверка перед любой операцией с данными.
// Если хранилище заблокировано — бросаем ошибку, а не отдаём пустые данные.
function requireUnlocked() {
  if (!unlockedKey || !vault) throw new Error('Хранилище заблокировано');
}

// Отправить сообщение в content script на вкладке.
// Если content script ещё не загружен (например, вкладка открыта до установки
// расширения), Chrome выдаст ошибку — тогда внедряем скрипт вручную.
async function sendToTab(tabId, message) {
  try {
    return await chrome.tabs.sendMessage(tabId, message);
  } catch (error) {
    await chrome.scripting.executeScript({ target: { tabId }, files: ['src/content.js'] });  // внедряем content script в открытую вкладку
    return chrome.tabs.sendMessage(tabId, message);
  }
}

// Получить активную вкладку — она нужна для автозаполнения.
async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

/* ------------------------------------------------------------------ */
/* 3. Проверка утечек (HIBP, k-anonymity)                              */
/* ------------------------------------------------------------------ */

// Как это работает:
// 1. Считаем SHA-1 от пароля. Это делается локально.
// 2. Отправляем в HIBP только первые 5 символов хеша.
// 3. Сервер возвращает список суффиксов и количество утечек.
// 4. Ищем свой суффикс локально.
// Так сервер не узнаёт пароль и даже полный хеш.
async function checkBreach(password) {
  const hash = await Crypto.sha1Hex(password);
  const prefix = hash.slice(0, 5);  // первые 5 символов — их видит сервер
  const suffix = hash.slice(5);
  if (!breachCache.has(prefix)) {  // кешируем ответ, чтобы не дёргать сервер лишний раз
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
/* 4. Буфер обмена и автоблокировка                                     */
/* ------------------------------------------------------------------ */

// Ставим таймер: через N секунд очистить буфер обмена.
// Chrome alarms работает даже когда service worker «спит»,
// обычный setTimeout для этого не подходит.
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

// Просим content script на активной вкладке очистить буфер.
// Если страница не поддерживает clipboard API, просто игнорируем.
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
/* 4b. Автоблокировка                                                  */
/* ------------------------------------------------------------------ */

// Настраиваем Chrome Idle API: браузер сам сообщит, что пользователь
// отошёл. Интервал проверки зависит от настроек автоблокировки.
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

// Будильник раз в 30 секунд проверяет, не пора ли заблокировать хранилище.
async function setupAlarms() {
  await applyIdleSettings();
  chrome.alarms.create(AUTOLOCK_ALARM, { periodInMinutes: 0.5 });
}

/* ------------------------------------------------------------------ */
/* 5. Контекстное меню                                                 */
/* ------------------------------------------------------------------ */

// Пункт «Заполнить паролем из KeyGuard» при клике правой кнопкой
// на поле ввода или на странице.
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

// Обработчик пункта меню: находим запись для сайта и просим
// content script заполнить форму.
async function handleContextMenu(info, tab) {
  if (!tab || !tab.id) return;
  if (info.menuItemId === 'keyguard-options') {
    chrome.runtime.openOptionsPage();  // открываем страницу настроек
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
/* 6. Маршрутизация сообщений                                          */
/* ------------------------------------------------------------------ */

// Сюда приходят команды от popup.js, options.js и content.js.
// Формат: { type: 'КОМАНДА', ...данные } → { ok: true, ...результат }.
// Важно: сначала ждём восстановления сессии после «сна» service worker.
// Подробный список команд — в README.md, раздел «Архитектура».
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
    // Создание нового хранилища. Пароль проверяем на длину
    // и сразу сохраняем зашифрованный конверт в storage.
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
    // Открытие хранилища: пароль проверяется в Crypto.unlockVault.
    // Ключ кладём в session storage, чтобы он пережил «сон» service worker.
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
    // Ручная блокировка из интерфейса.
    case 'LOCK': {
      await lock('manual');
      return { ok: true, state: await getState() };
    }
    // Список записей для popup и страницы настроек.
    case 'GET_ENTRIES': {
      requireUnlocked();
      touch();
      return { ok: true, entries: sortEntries(vault.entries) };
    }
    // Добавить новую запись или обновить существующую по id.
    // Если пароль изменился, обновляем дату passwordUpdatedAt —
    // она нужна для аудита «старых» паролей.
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
    // Удаление записи по id.
    case 'DELETE_ENTRY': {
      requireUnlocked();
      vault.entries = vault.entries.filter((entry) => entry.id !== message.id);
      await persistVault();
      touch();
      return { ok: true, entries: sortEntries(vault.entries) };
    }
    // Переключить «звёздочку» у записи.
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
    // Смена мастер-пароля: сначала проверяем текущий пароль,
    // затем перешифровываем всё хранилище новым ключом.
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
    // Настройки: автоблокировка, буфер обмена, генератор.
    case 'GET_SETTINGS': {
      return { ok: true, settings: await Storage.getSettings() };
    }
    case 'SET_SETTINGS': {
      const settings = await Storage.setSettings(message.settings || {});
      await applyIdleSettings();
      return { ok: true, settings };
    }
    // Экспорт: отдаём зашифрованный конверт. Открытых паролей в нём нет.
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
    // Импорт: проверяем структуру файла и пароль, затем заменяем хранилище.
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
    // Полное удаление хранилища и настроек (опасная зона).
    case 'RESET_VAULT': {
      unlockedKey = null;
      vault = null;
      record = null;
      await Storage.resetAll();
      return { ok: true, state: await getState() };
    }
    // Проверка пароля по базе утечек (см. checkBreach выше).
    case 'CHECK_BREACH': {
      const password = String(message.password || '');
      if (!password) throw new Error('Пароль не задан');
      return { ok: true, ...(await checkBreach(password)) };
    }
    // Спросить у content script, есть ли на странице форма логина.
    case 'GET_PAGE_FORM': {
      const tab = tabId ? { id: tabId } : await getActiveTab();
      if (!tab?.id) throw new Error('Не удалось определить вкладку');
      const form = await sendToTab(tab.id, { type: 'KEYGUARD_GET_FORM' });
      return { ok: true, form };
    }
    // Автозаполнение: передаём запись в content script.
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
    // Запланировать очистку буфера обмена после копирования пароля.
    case 'SCHEDULE_CLIPBOARD_CLEAR': {
      await scheduleClipboardClear(message.seconds);
      return { ok: true };
    }
    // Content script сообщает, что форма отправлена. Решаем,
    // что показать: «сохранить новый пароль» или «обновить существующий».
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
    // Пользователь нажал «Сохранить» или «Обновить» в баннере на сайте.
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

// Точка входа для всех сообщений. Возвращаем true, чтобы Chrome
// ждал асинхронный sendResponse и не закрыл канал раньше времени.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then((response) => sendResponse(response))
    .catch((error) => sendResponse({ ok: false, error: error?.message || 'Внутренняя ошибка' }));
  return true;
});

/* ------------------------------------------------------------------ */
/* 7. События жизненного цикла                                         */
/* ------------------------------------------------------------------ */

// chrome.runtime.onInstalled срабатывает при установке и обновлении.
// Здесь создаём меню, таймеры и пробуем восстановить сессию.
chrome.runtime.onInstalled.addListener(async () => {
  setupContextMenus();
  await setupAlarms();
  await ensureSession();
});

// onStartup — при запуске браузера.
chrome.runtime.onStartup.addListener(async () => {
  setupContextMenus();
  await setupAlarms();
  await ensureSession();
});

// Будильники: проверка простоя и отложенная очистка буфера.
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

// Пользователь отошёл от компьютера / вернулся / экран заблокирован.
chrome.idle.onStateChanged.addListener(async (state) => {
  if (state === 'active') return;
  const settings = await Storage.getSettings();
  if (settings.lockOnIdle && unlockedKey) await lock('idle');
});

// Клик по пункту контекстного меню.
chrome.contextMenus.onClicked.addListener((info, tab) => {
  handleContextMenu(info, tab).catch(() => {});
});

// Если настройки изменились на другой странице, обновляем таймеры.
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
