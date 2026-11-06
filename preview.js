/**
 * Интерактивный макет попапа KeyGuard.
 * Загружает настоящий popup.html в iframe и подменяет chrome.runtime
 * демонстрационными данными, чтобы интерфейс можно было посмотреть
 * без установки расширения.
 */
(() => {
  'use strict';

  const MOCK_CHROME = `
    (() => {
      const settings = {
        autoLockMinutes: 5,
        clipboardClearSeconds: 30,
        lockOnIdle: true,
        breachCheck: true,
        generator: { length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: true }
      };
      const now = new Date().toISOString();
      let unlocked = true;
      let entries = [
        {
          id: 'demo-1', type: 'login', title: 'Школьный портал',
          username: 'student@school10.ru', password: 'SchoolPass!2026',
          url: 'http://localhost:8000', notes: 'Демо-запись для макета.',
          card: {}, favorite: true, totp: 'JBSWY3DPEHPK3PXP',
          createdAt: now, updatedAt: now, passwordUpdatedAt: now
        },
        {
          id: 'demo-2', type: 'login', title: 'Почта',
          username: 'student@school10.ru', password: 'password123',
          url: 'https://mail.example.com', notes: '',
          card: {}, favorite: false, totp: '',
          createdAt: now, updatedAt: now, passwordUpdatedAt: now
        },
        {
          id: 'demo-3', type: 'card', title: 'Учебная карта',
          username: '', password: '', url: '', notes: '',
          card: { number: '4111 1111 1111 1111', holder: 'IVAN IVANOV', expiry: '12/28', cvv: '123' },
          favorite: false, totp: '', createdAt: now, updatedAt: now, passwordUpdatedAt: null
        },
        {
          id: 'demo-4', type: 'note', title: 'Идеи для проекта',
          username: '', password: '', url: '', notes: 'Добавить синхронизацию и поддержку passkeys.',
          card: {}, favorite: false, totp: '', createdAt: now, updatedAt: now, passwordUpdatedAt: null
        }
      ];
      const clone = (value) => JSON.parse(JSON.stringify(value));
      const state = () => ({ hasVault: true, unlocked, settings });
      const listeners = [];
      const respond = (callback, response) => {
        if (typeof callback === 'function') setTimeout(() => callback(response), 0);
        return Promise.resolve(response);
      };
      window.chrome = {
        runtime: {
          lastError: null,
          sendMessage(message, callback) {
            let response = { ok: true };
            switch (message && message.type) {
              case 'GET_STATE':
                response = { ok: true, ...state() };
                break;
              case 'GET_ENTRIES':
                response = unlocked
                  ? { ok: true, entries: clone(entries) }
                  : { ok: false, error: 'Хранилище заблокировано' };
                break;
              case 'PING':
                response = { ok: true, state: state() };
                break;
              case 'UPSERT_ENTRY': {
                const entry = {
                  ...message.entry,
                  id: message.entry.id || 'demo-' + Date.now(),
                  createdAt: message.entry.createdAt || now,
                  updatedAt: now
                };
                const index = entries.findIndex((item) => item.id === entry.id);
                if (index >= 0) entries[index] = entry;
                else entries.unshift(entry);
                response = { ok: true, entries: clone(entries), entry };
                break;
              }
              case 'DELETE_ENTRY':
                entries = entries.filter((item) => item.id !== message.id);
                response = { ok: true, entries: clone(entries) };
                break;
              case 'TOGGLE_FAVORITE': {
                const entry = entries.find((item) => item.id === message.id);
                if (entry) entry.favorite = !entry.favorite;
                response = { ok: true, entries: clone(entries) };
                break;
              }
              case 'LOCK':
                unlocked = false;
                response = { ok: true, state: state() };
                break;
              case 'UNLOCK':
                unlocked = Boolean(message.password);
                response = unlocked
                  ? { ok: true, state: state() }
                  : { ok: false, error: 'Введите мастер-пароль' };
                break;
              case 'CHECK_BREACH':
                response = { ok: true, breached: false, count: 0 };
                break;
              case 'FILL_ON_PAGE':
                response = { ok: true, filled: true };
                break;
              case 'SCHEDULE_CLIPBOARD_CLEAR':
              case 'CHANGE_MASTER_PASSWORD':
                response = { ok: true, state: state() };
                break;
              default:
                response = { ok: true };
            }
            return respond(callback, response);
          },
          onMessage: { addListener(fn) { listeners.push(fn); } },
          openOptionsPage() {}
        },
        tabs: {
          create(options) {
            if (options && options.url) window.open(options.url, '_blank', 'noopener');
          }
        }
      };
    })();
  `;

  async function init() {
    const frame = document.getElementById('popup-frame');
    const errorNode = document.getElementById('preview-error');
    try {
      const response = await fetch('src/popup.html');
      if (!response.ok) throw new Error('Не удалось загрузить popup.html');
      let html = await response.text();
      html = html
        .replace('href="styles.css"', 'href="/src/styles.css"')
        .replace('src="lib/crypto.js"', 'src="/src/lib/crypto.js"')
        .replace('src="lib/generator.js"', 'src="/src/lib/generator.js"')
        .replace('src="lib/totp.js"', 'src="/src/lib/totp.js"')
        .replace(
          '<script src="popup.js"></script>',
          `<script>${MOCK_CHROME}</script>\n    <script src="/src/popup.js"></script>`
        );
      frame.srcdoc = html;
    } catch (error) {
      errorNode.textContent = `Не удалось открыть макет: ${error.message}. Запустите проект через локальный сервер (npm run serve) и откройте http://localhost:8000/preview.html.`;
      errorNode.hidden = false;
    }
  }

  init();
})();
