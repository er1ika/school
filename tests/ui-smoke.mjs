import { JSDOM, VirtualConsole } from 'jsdom';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const errors = [];
let passed = 0, failed = 0;
function check(cond, msg) {
  if (cond) { passed++; console.log('  ✓ ' + msg); }
  else { failed++; console.error('  ✗ ' + msg); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const settings = {
  autoLockMinutes: 5,
  clipboardClearSeconds: 30,
  lockOnIdle: true,
  breachCheck: true,
  generator: { length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: true }
};
const entries = [
  { id: '1', type: 'login', title: 'Школьный портал', username: 'student@school10.ru', password: 'password123', url: 'http://localhost:8000', notes: 'Тестовая запись', card: {}, favorite: true, totp: 'JBSWY3DPEHPK3PXP', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), passwordUpdatedAt: new Date().toISOString() },
  { id: '2', type: 'card', title: 'Карта', username: '', password: '', url: '', notes: '', card: { number: '4111 1111 1111 1111', holder: 'IVAN IVANOV', expiry: '12/28', cvv: '123' }, favorite: false, totp: '', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), passwordUpdatedAt: null },
  { id: '3', type: 'note', title: 'Заметка', username: '', password: '', url: '', notes: 'Не забыть про проект', card: {}, favorite: false, totp: '', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), passwordUpdatedAt: null }
];

function makeChrome({ onSend } = {}) {
  const messageListeners = [];
  return {
    runtime: {
      lastError: null,
      sendMessage(message, callback) {
        let response;
        if (onSend) response = onSend(message);
        else if (message.type === 'GET_STATE') response = { ok: true, hasVault: true, unlocked: true, settings };
        else if (message.type === 'GET_ENTRIES') response = { ok: true, entries };
        else if (message.type === 'PING') response = { ok: true, state: { hasVault: true, unlocked: true, settings } };
        else if (message.type === 'UPSERT_ENTRY') response = { ok: true, entries: [message.entry, ...entries], entry: message.entry };
        else if (message.type === 'LOCK') response = { ok: true, state: { hasVault: true, unlocked: false, settings } };
        else response = { ok: true };
        if (typeof callback === 'function') setTimeout(() => callback(response), 0);
        return Promise.resolve(response);
      },
      onMessage: { addListener(fn) { messageListeners.push(fn); } },
      openOptionsPage() {}
    },
    tabs: { create() {}, query() {} },
    action: { openOptionsPage() {} },
    storage: { local: { get() {}, set() {} }, session: { get() {}, set() {} } },
    _messageListeners: messageListeners
  };
}

function stubWindow(window, chrome) {
  Object.defineProperty(window, 'chrome', { value: chrome, configurable: true });
  Object.defineProperty(window, 'crypto', { value: globalThis.crypto, configurable: true });
  Object.defineProperty(window.navigator, 'clipboard', { value: { writeText: async () => {} }, configurable: true });
  window.Element.prototype.getBoundingClientRect = function () {
    return { width: 120, height: 24, top: 0, left: 0, right: 120, bottom: 24, x: 0, y: 0 };
  };
  window.getComputedStyle = () => ({ visibility: 'visible', display: 'block', opacity: '1' });
}

async function loadPage(file, chrome, beforeParseExtra) {
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('jsdomError', (e) => errors.push('jsdomError: ' + e.message + ' | ' + (e.detail?.stack || e.stack || '')));
  virtualConsole.on('error', (...args) => errors.push('console.error: ' + args.join(' ')));
  const dom = await JSDOM.fromFile(path.join(root, file), {
    runScripts: 'dangerously',
    resources: 'usable',
    pretendToBeVisual: true,
    virtualConsole,
    beforeParse(window) {
      stubWindow(window, chrome);
      if (beforeParseExtra) beforeParseExtra(window);
    }
  });
  await new Promise((resolve) => dom.window.addEventListener('load', resolve));
  await sleep(150);
  return dom;
}

async function testPopup() {
  console.log('\nПопап KeyGuard');
  const chrome = makeChrome();
  const dom = await loadPage('src/popup.html', chrome);
  const { document } = dom.window;
  check(document.querySelectorAll('#entries-list .entry').length === 3, 'рендерятся 3 записи');
  check(document.querySelector('#vault-count').textContent.includes('3 записи'), 'счётчик записей обновлён');
  check(document.querySelector('#screen-vault').hidden === false, 'открыт экран хранилища');

  document.querySelector('#entries-list .entry').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  await sleep(30);
  check(document.querySelector('#screen-detail').hidden === false, 'карточка записи открывается');
  check(document.querySelector('#detail-body').textContent.includes('password123') === false, 'пароль скрыт по умолчанию');
  document.querySelector('[data-reveal="password"]').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  await sleep(10);
  check(document.querySelector('[data-secret="password"]').textContent === 'password123', 'пароль раскрывается по кнопке');
  check(document.querySelector('#totp-code').textContent.length === 6, 'TOTP-код генерируется');

  document.querySelector('#btn-detail-back').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  await sleep(20);
  check(document.querySelector('#screen-vault').hidden === false, 'возврат к списку работает');

  document.querySelector('#btn-add').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  await sleep(20);
  check(Boolean(document.querySelector('#entry-title')), 'редактор открывается');
  document.querySelector('#entry-title').value = 'Новая запись';
  document.querySelector('#entry-username').value = 'test';
  document.querySelector('#entry-password').value = 'NewStrongPass!123';
  document.querySelector('#entry-save').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  await sleep(40);
  check(document.querySelector('#modal-root').children.length === 0, 'редактор закрывается после сохранения');

  document.querySelector('#btn-generator').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  await sleep(20);
  const generated = document.querySelector('#gen-password').textContent;
  check(generated.length === 20, 'генератор создаёт пароль длиной 20');
  check(document.querySelector('#gen-strength').children.length === 4, 'индикатор надёжности отрисован');
  document.querySelector('#gen-copy').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  await sleep(10);
  document.querySelector('#modal-root').innerHTML = '';

  document.querySelector('#btn-lock').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  await sleep(30);
  check(document.querySelector('#screen-lock').hidden === false, 'блокировка возвращает экран ввода пароля');
  check(document.querySelector('#unlock-form').hidden === false, 'форма разблокировки видна');
  check(errors.length === 0, 'нет ошибок в консоли попапа: ' + errors.join(' | '));
  dom.window.close();
}

async function testOptions() {
  console.log('\nСтраница настроек');
  const chrome = makeChrome();
  const dom = await loadPage('src/options.html', chrome);
  const { document } = dom.window;
  check(document.querySelector('#status-text').textContent === 'Разблокировано', 'статус хранилища отображается');
  check(document.querySelector('#options-gen-password').textContent.length === 20, 'генератор на странице настроек работает');
  check(document.querySelector('#stat-weak').textContent !== '', 'аудит считает слабые пароли');
  check(document.querySelector('#change-submit').disabled === false, 'форма смены пароля активна');

  document.querySelector('[data-tab="audit"]').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  await sleep(20);
  check(document.querySelector('#panel-audit').classList.contains('active'), 'вкладка аудита открывается');
  check(document.querySelectorAll('#list-weak .audit-item').length === 1, 'слабый пароль найден в аудите');

  document.querySelector('[data-tab="generator"]').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  await sleep(10);
  check(document.querySelector('#panel-generator').classList.contains('active'), 'вкладка генератора открывается');

  document.querySelector('[data-tab="data"]').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  await sleep(10);
  check(document.querySelector('#panel-data').classList.contains('active'), 'вкладка данных открывается');

  check(errors.length === 0, 'нет ошибок в консоли настроек: ' + errors.join(' | '));
  dom.window.close();
}

async function testContent() {
  console.log('\nКонтент-скрипт и демо-сайт');
  const sent = [];
  const chrome = makeChrome({
    onSend(message) {
      sent.push(message);
      if (message.type === 'KEYGUARD_SUBMITTED') {
        return { ok: true, prompt: { mode: 'save', entry: { title: 'Школьный портал', username: message.credentials.username } } };
      }
      return { ok: true };
    }
  });
  const dom = await loadPage('demo-site/index.html', chrome);
  const { window } = dom;
  const { document } = window;
  const contentCode = fs.readFileSync(path.join(root, 'src/content.js'), 'utf8');
  window.eval(contentCode);
  await sleep(30);

  document.querySelector('#login-email').value = 'student@school10.ru';
  document.querySelector('#login-password').value = 'DemoPass!2026';
  document.querySelector('#login-form').dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
  await sleep(60);
  const host = document.querySelector('#__keyguard_host__');
  check(Boolean(host && host.shadowRoot), 'создаётся shadow DOM для баннера');
  const panel = host?.shadowRoot?.querySelector('.kg-panel');
  check(Boolean(panel), 'баннер сохранения пароля появляется');
  check(panel?.textContent.includes('Сохранить пароль'), 'баннер предлагает сохранить пароль');
  const submitted = sent.find((m) => m.type === 'KEYGUARD_SUBMITTED');
  check(submitted?.credentials?.password === 'DemoPass!2026', 'в расширение уходит пароль из формы');
  panel?.querySelector('.kg-btn-primary')?.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await sleep(30);
  check(sent.some((m) => m.type === 'KEYGUARD_PROMPT_ACTION' && m.action === 'save'), 'кнопка баннера отправляет сохранение');

  const formInfo = {};
  chrome._messageListeners.forEach((fn) => fn({ type: 'KEYGUARD_GET_FORM' }, {}, (r) => Object.assign(formInfo, r)));
  check(formInfo.found === true, 'форма логина определяется');

  chrome._messageListeners.forEach((fn) => fn({ type: 'KEYGUARD_FILL', entry: entries[0] }, {}, () => {}));
  await sleep(20);
  check(document.querySelector('#login-password').value === 'password123', 'пароль подставляется в форму');
  check(document.querySelector('#login-email').value === 'student@school10.ru', 'логин подставляется в форму');

  document.querySelector('#change-email').value = 'student@school10.ru';
  document.querySelector('#current-password').value = 'OldPass!2026';
  document.querySelector('#new-password').value = 'BrandNewPass!2026';
  document.querySelector('#password-form').dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
  await sleep(60);
  const submittedChange = sent.filter((m) => m.type === 'KEYGUARD_SUBMITTED').pop();
  check(submittedChange?.credentials?.password === 'BrandNewPass!2026', 'в форме смены пароля берётся новое поле');

  check(errors.length === 0, 'нет ошибок в консоли демо-сайта: ' + errors.join(' | '));
  dom.window.close();
}

await testPopup();
await testOptions();
await testContent();
console.log(`\nРезультат UI-тестов: ${passed} пройдено, ${failed} провалено`);
if (failed > 0) process.exit(1);
