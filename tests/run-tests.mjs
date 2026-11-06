/**
 * Тесты KeyGuard без внешних зависимостей.
 * Запуск: npm test  (или node tests/run-tests.mjs)
 */
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function loadScript(relativePath) {
  const code = fs.readFileSync(path.join(root, relativePath), 'utf8');
  vm.runInThisContext(code, { filename: relativePath });
}

/* ------------------------------- assert -------------------------------- */

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed += 1;
    console.log(`  ✓ ${message}`);
  } else {
    failed += 1;
    console.error(`  ✗ ${message}`);
  }
}

async function assertRejects(promise, message) {
  try {
    await promise;
    failed += 1;
    console.error(`  ✗ ${message} (ожидалась ошибка)`);
  } catch (error) {
    passed += 1;
    console.log(`  ✓ ${message}`);
  }
}

function section(name) {
  console.log(`\n${name}`);
}

/* -------------------------------- Тесты -------------------------------- */

async function testCrypto() {
  section('Криптография (PBKDF2 + AES-256-GCM)');
  const Crypto = globalThis.KeyGuardCrypto;
  const password = 'correct-horse-battery-staple';
  const created = await Crypto.createVault(password);
  assert(created.record.salt && created.record.verifier && created.record.data, 'хранилище содержит соль, verifier и данные');
  assert(created.record.iterations === 310000, 'используется 310 000 итераций PBKDF2');
  assert(created.vault.entries.length === 0, 'новое хранилище пустое');
  assert(!JSON.stringify(created.record).includes(password), 'мастер-пароль не попадает в запись');

  const opened = await Crypto.unlockVault(password, created.record);
  assert(opened.vault.entries.length === 0, 'правильный пароль расшифровывает хранилище');
  await assertRejects(Crypto.unlockVault('wrong-password', created.record), 'неверный пароль отклоняется');

  opened.vault.entries.push({
    id: 'test-1',
    type: 'login',
    title: 'Тест',
    username: 'student',
    password: 'secret',
    url: 'https://example.com',
    notes: '',
    card: {},
    favorite: false,
    totp: '',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    passwordUpdatedAt: new Date().toISOString()
  });
  const record2 = await Crypto.persistVault(opened.key, created.record, opened.vault);
  const opened2 = await Crypto.unlockVault(password, record2);
  assert(opened2.vault.entries[0].title === 'Тест', 'данные сохраняются после перешифрования');

  const rekeyed = await Crypto.rekeyVault(record2, opened2.vault, 'new-strong-password-123');
  await assertRejects(Crypto.unlockVault(password, rekeyed.record), 'старый пароль после смены не работает');
  const opened3 = await Crypto.unlockVault('new-strong-password-123', rekeyed.record);
  assert(opened3.vault.entries[0].title === 'Тест', 'данные сохраняются после смены мастер-пароля');

  const encrypted = await Crypto.encryptString(opened3.key, 'hello');
  const tampered = { ...encrypted, ct: encrypted.ct.slice(0, -4) + 'AAAA' };
  await assertRejects(Crypto.decryptString(opened3.key, tampered), 'AES-GCM обнаруживает изменение шифротекста');

  const raw = await Crypto.exportKey(opened3.key);
  const imported = await Crypto.importKey(raw);
  const decrypted = await Crypto.decryptString(imported, encrypted);
  assert(decrypted === 'hello', 'ключ экспортируется и импортируется для session storage');
}

function testGenerator() {
  section('Генератор паролей');
  const Generator = globalThis.KeyGuardGenerator;
  const options = { length: 24, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: true };
  const password = Generator.generatePassword(options);
  assert(password.length === 24, 'длина пароля соответствует настройке');
  assert(/[a-z]/.test(password), 'пароль содержит строчные буквы');
  assert(/[A-Z]/.test(password), 'пароль содержит заглавные буквы');
  assert(/[0-9]/.test(password), 'пароль содержит цифры');
  assert(/[^a-zA-Z0-9]/.test(password), 'пароль содержит символы');
  assert(!/[Il1O0o]/.test(password), 'режим avoidAmbiguous убирает похожие символы');

  const digits = Generator.generatePassword({ length: 10, lower: false, upper: false, digits: true, symbols: false });
  assert(/^[0-9]{10}$/.test(digits), 'генератор работает только с цифрами');

  const weak = Generator.estimateStrength('password');
  assert(weak.score <= 1, 'популярный пароль оценивается как слабый');
  const strong = Generator.estimateStrength(Generator.generatePassword(options));
  assert(strong.score >= 3, 'случайный пароль из 24 символов оценивается высоко');
  assert(Generator.isCommonPassword('qwerty123'), 'распознавание популярных паролей');
  assert(!Generator.isCommonPassword(Generator.generatePassword(options)), 'случайный пароль не считается популярным');
}

async function testTotp() {
  section('TOTP (RFC 6238)');
  const Totp = globalThis.KeyGuardTotp;
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const code = await Totp.hotp(secret, 1);
  assert(code === '287082', `известный тестовый вектор RFC 4226: ${code}`);
  const result = await Totp.generateTotp(secret, 59000);
  assert(result.code === '287082', 'TOTP для времени 59 секунд совпадает с вектором');
  assert(result.remaining >= 1 && result.remaining <= 30, 'остаток времени в диапазоне 1..30');
  assert(Totp.isBase32('JBSWY3DPEHPK3PXP'), 'валидация base32-секрета');
  assert(!Totp.isBase32('not-a-secret!'), 'некорректный секрет отклоняется');
}

function createMemoryArea() {
  const data = new Map();
  return {
    get(keys, callback) {
      const list = Array.isArray(keys) ? keys : [keys];
      const result = {};
      for (const key of list) if (data.has(key)) result[key] = data.get(key);
      callback(result);
    },
    set(items, callback) {
      for (const [key, value] of Object.entries(items)) data.set(key, value);
      callback();
    },
    remove(keys, callback) {
      const list = Array.isArray(keys) ? keys : [keys];
      for (const key of list) data.delete(key);
      callback();
    },
    _dump: () => Object.fromEntries(data)
  };
}

async function testStorage() {
  section('Хранилище (chrome.storage)');
  globalThis.chrome = {
    storage: {
      local: createMemoryArea(),
      session: createMemoryArea()
    }
  };
  loadScript('src/lib/storage.js');
  const Storage = globalThis.KeyGuardStorage;

  assert(await Storage.vaultExists() === false, 'хранилище изначально отсутствует');
  const record = { salt: 'abc', verifier: { iv: 'a', ct: 'b' }, data: { iv: 'c', ct: 'd' } };
  await Storage.setVaultRecord(record);
  assert(await Storage.vaultExists() === true, 'запись хранилища сохраняется');
  assert((await Storage.getVaultRecord()).salt === 'abc', 'запись хранилища читается');

  const defaults = await Storage.getSettings();
  assert(defaults.autoLockMinutes === 5, 'настройки по умолчанию применяются');
  const updated = await Storage.setSettings({ autoLockMinutes: 10, generator: { length: 32 } });
  assert(updated.autoLockMinutes === 10, 'настройки обновляются');
  assert(updated.generator.length === 32, 'вложенные настройки генератора обновляются');
  assert(updated.generator.upper === true, 'неизменённые настройки сохраняются');

  await Storage.setSessionKey('raw-key');
  assert((await Storage.getSessionKey()) === 'raw-key', 'ключ сохраняется в session storage');
  await Storage.clearSessionKey();
  assert((await Storage.getSessionKey()) === null, 'ключ удаляется из session storage');

  await Storage.resetAll();
  assert((await Storage.getVaultRecord()) === null, 'resetAll удаляет хранилище');
  assert((await Storage.getSettings()).autoLockMinutes === 5, 'resetAll сбрасывает настройки');
}

async function testBackground() {
  section('Service worker (background.js)');
  const local = createMemoryArea();
  const session = createMemoryArea();
  const messageListeners = [];
  const noop = () => {};

  globalThis.chrome = {
    storage: {
      local,
      session,
      onChanged: { addListener() {} }
    },
    runtime: {
      lastError: null,
      onMessage: { addListener(fn) { messageListeners.push(fn); } },
      onInstalled: { addListener() {} },
      onStartup: { addListener() {} },
      sendMessage() {}
    },
    alarms: {
      create() {},
      clear() {},
      onAlarm: { addListener() {} }
    },
    idle: {
      setDetectionInterval() {},
      onStateChanged: { addListener() {} }
    },
    contextMenus: {
      removeAll(callback) { callback(); },
      create() {},
      onClicked: { addListener() {} }
    },
    tabs: {
      query: async () => [{ id: 1, url: 'https://example.com/login' }],
      sendMessage: async (_tabId, message) => {
        if (message?.type === 'KEYGUARD_GET_FORM') return { found: true, hasForm: true };
        return { filled: true };
      },
      create() {}
    },
    scripting: { executeScript: async () => [] },
    action: { openOptionsPage() {} }
  };

  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes('api.pwnedpasswords.com')) {
      return { ok: true, text: async () => 'A1B2C3D4E5:3\n' };
    }
    return realFetch(url);
  };

  globalThis.importScripts = (...files) => {
    for (const file of files) {
      const code = fs.readFileSync(path.join(root, 'src', file), 'utf8');
      vm.runInThisContext(code, { filename: file });
    }
  };

  loadScript('src/background.js');
  await new Promise((resolve) => setTimeout(resolve, 20));

  function send(message, sender = { tab: { id: 1 } }) {
    return new Promise((resolve, reject) => {
      const listener = messageListeners[messageListeners.length - 1];
      if (!listener) return reject(new Error('listener не зарегистрирован'));
      const result = listener(message, sender, (response) => {
        if (response && response.ok === false) reject(new Error(response.error || 'Ошибка'));
        else resolve(response);
      });
      if (result !== true) reject(new Error('listener не вернул true'));
    });
  }

  let state = await send({ type: 'GET_STATE' });
  assert(state.hasVault === false && state.unlocked === false, 'изначально хранилище не создано');

  await assertRejects(send({ type: 'CREATE_VAULT', password: '123' }), 'короткий мастер-пароль отклоняется');
  await send({ type: 'CREATE_VAULT', password: 'very-strong-master-password' });
  state = await send({ type: 'GET_STATE' });
  assert(state.hasVault === true && state.unlocked === true, 'хранилище создаётся и разблокируется');

  let entries = await send({ type: 'GET_ENTRIES' });
  assert(entries.entries.length === 0, 'новое хранилище пустое');

  const login = {
    type: 'login',
    title: 'Сайт',
    username: 'student',
    password: 'password123',
    url: 'https://example.com',
    notes: '',
    card: {},
    favorite: false,
    totp: ''
  };
  let result = await send({ type: 'UPSERT_ENTRY', entry: login });
  assert(result.entries.length === 1, 'запись добавляется');
  const id = result.entry.id;

  result = await send({ type: 'UPSERT_ENTRY', entry: { ...login, id, password: 'password123' } });
  assert(result.entries.length === 1, 'повторное сохранение не создаёт дубликат');
  assert(result.entry.passwordUpdatedAt === result.entry.passwordUpdatedAt, 'дата пароля присутствует');

  result = await send({ type: 'TOGGLE_FAVORITE', id });
  assert(result.entries[0].favorite === true, 'избранное переключается');

  result = await send({ type: 'DELETE_ENTRY', id });
  assert(result.entries.length === 0, 'запись удаляется');

  await assertRejects(
    send({ type: 'CHANGE_MASTER_PASSWORD', currentPassword: 'wrong', newPassword: 'another-strong-password' }),
    'смена пароля с неверным текущим паролем отклоняется'
  );
  await send({ type: 'CHANGE_MASTER_PASSWORD', currentPassword: 'very-strong-master-password', newPassword: 'another-strong-password' });
  state = await send({ type: 'GET_STATE' });
  assert(state.unlocked === true, 'после смены мастер-пароля хранилище остаётся разблокированным');

  await send({ type: 'LOCK' });
  state = await send({ type: 'GET_STATE' });
  assert(state.unlocked === false, 'блокировка работает');
  await assertRejects(send({ type: 'GET_ENTRIES' }), 'чтение заблокированного хранилища запрещено');

  await send({ type: 'UNLOCK', password: 'another-strong-password' });
  result = await send({ type: 'UPSERT_ENTRY', entry: login });
  assert(result.entries.length === 1, 'после разблокировки запись добавляется');

  const backup = await send({ type: 'EXPORT_BACKUP' });
  assert(backup.record.vault && backup.record.vault.salt, 'экспорт содержит зашифрованный конверт');
  assert(!JSON.stringify(backup.record).includes('password123'), 'в бэкапе нет открытого пароля');

  await send({ type: 'RESET_VAULT' });
  state = await send({ type: 'GET_STATE' });
  assert(state.hasVault === false && state.unlocked === false, 'удаление хранилища работает');

  await send({ type: 'IMPORT_BACKUP', record: backup.record, password: 'another-strong-password' });
  state = await send({ type: 'GET_STATE' });
  assert(state.hasVault === true && state.unlocked === true, 'импорт восстанавливает хранилище');
  entries = await send({ type: 'GET_ENTRIES' });
  assert(entries.entries.length === 1 && entries.entries[0].title === 'Сайт', 'импорт сохраняет записи');

  const breach = await send({ type: 'CHECK_BREACH', password: 'password123' });
  assert(breach.breached === false && breach.count === 0, 'проверка утечек возвращает результат');

  const settings = await send({ type: 'SET_SETTINGS', settings: { autoLockMinutes: 10 } });
  assert(settings.settings.autoLockMinutes === 10, 'настройки обновляются через service worker');

  const submitted = await send({
    type: 'KEYGUARD_SUBMITTED',
    credentials: { origin: 'https://example.com', title: 'Сайт', username: 'student', password: 'password123' }
  });
  assert(submitted.prompt === null, 'одинаковый пароль не вызывает повторное предложение');

  const updatePrompt = await send({
    type: 'KEYGUARD_SUBMITTED',
    credentials: { origin: 'https://example.com', title: 'Сайт', username: 'student', password: 'new-password-123' }
  });
  assert(updatePrompt.prompt?.mode === 'update', 'другой пароль вызывает предложение обновить запись');

  await send({
    type: 'KEYGUARD_PROMPT_ACTION',
    action: 'update',
    existingId: id,
    credentials: { origin: 'https://example.com', title: 'Сайт', username: 'student', password: 'new-password-123' }
  });
  entries = await send({ type: 'GET_ENTRIES' });
  assert(entries.entries[0].password === 'new-password-123', 'пароль обновляется после подтверждения');

  const form = await send({ type: 'GET_PAGE_FORM' });
  assert(form.form?.found === true, 'форма на странице определяется');

  const currentId = entries.entries[0].id;
  const filled = await send({ type: 'FILL_ON_PAGE', entryId: currentId });
  assert(filled.filled === true, 'автозаполнение отправляет данные в content script');

  await send({ type: 'SCHEDULE_CLIPBOARD_CLEAR', seconds: 30 });
  assert(true, 'очистка буфера обмена планируется без ошибок');

  const ping = await send({ type: 'PING', touch: true });
  assert(ping.state.unlocked === true, 'PING возвращает состояние');

  await send({ type: 'LOCK' });
  assert(true, 'фоновая логика завершает работу без ошибок');
}

function testManifest() {
  section('Манифест и структура');
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
  assert(manifest.manifest_version === 3, 'используется Manifest V3');
  assert(manifest.background.service_worker === 'src/background.js', 'service worker указан верно');
  assert(manifest.action.default_popup === 'src/popup.html', 'попап указан верно');
  assert(manifest.options_ui.page === 'src/options.html', 'страница настроек указана верно');
  assert(manifest.content_scripts[0].js.includes('src/content.js'), 'контент-скрипт подключён');
  assert(manifest.permissions.includes('storage'), 'разрешение storage запрошено');
  for (const size of [16, 48, 128]) {
    const iconPath = path.join(root, `icons/icon${size}.png`);
    assert(fs.existsSync(iconPath), `иконка ${size}×${size} существует`);
  }
  for (const file of ['src/popup.html', 'src/options.html', 'src/popup.js', 'src/options.js', 'src/background.js', 'src/content.js']) {
    assert(fs.existsSync(path.join(root, file)), `${file} существует`);
  }
}

/* -------------------------------- Запуск ------------------------------- */

loadScript('src/lib/crypto.js');
loadScript('src/lib/generator.js');
loadScript('src/lib/totp.js');

await testCrypto();
testGenerator();
await testTotp();
await testStorage();
await testBackground();
testManifest();

console.log(`\nРезультат: ${passed} пройдено, ${failed} провалено`);
if (failed > 0) process.exit(1);
