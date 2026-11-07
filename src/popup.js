/**
 * KeyGuard Popup — интерфейс хранилища.
 */
(() => {
  'use strict';

  /* =====================================================================
     КАК ЧИТАТЬ ЭТОТ ФАЙЛ
     ---------------------------------------------------------------------
     popup.js отвечает за окно, которое открывается по клику на иконку.
     1. Утилиты: экранирование, тосты, копирование, общение с background.
     2. Состояние и переключение экранов (блокировка / хранилище / запись).
     3. Список записей: фильтры, поиск, карточки.
     4. Детальная карточка: пароль, карта, TOTP.
     5. Редактор записи и генератор паролей.
     6. Подтверждение удаления и обработчики событий.

     Пароли в этом файле не хранятся: интерфейс получает их из background
     через chrome.runtime.sendMessage и сразу показывает/копирует.
     ===================================================================== */

  /* --- 1. Короткие помощники и утилиты ------------------------------- */

  // $ и $$ — сокращения для querySelector / querySelectorAll.
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

  // Всё состояние интерфейса в одном объекте. Так проще понимать,
  // что именно меняется при кликах.
  const state = {
    hasVault: false,
    unlocked: false,
    settings: null,  // настройки из background
    entries: [],  // записи, полученные из background
    filter: 'all',  // текущий фильтр: all/favorite/login/card/note
    query: '',  // строка поиска
    currentEntryId: null,
    editingEntryId: null,
    currentEntry: null,  // запись, открытая в детальной карточке
    currentTotpCode: '',
    totpTimer: null,  // таймер обновления TOTP-кода
    generatorOptions: null,
    generatorPassword: '',
    lastTouch: 0
  };

  // Палитра аватарок. Цвет выбирается по названию записи (hashString),
  // поэтому у одной и той же записи он всегда одинаковый.
  const GRADIENTS = [
    'linear-gradient(135deg, #8b5cf6, #6366f1)',
    'linear-gradient(135deg, #06b6d4, #3b82f6)',
    'linear-gradient(135deg, #f59e0b, #ef4444)',
    'linear-gradient(135deg, #10b981, #06b6d4)',
    'linear-gradient(135deg, #ec4899, #8b5cf6)',
    'linear-gradient(135deg, #f97316, #facc15)',
    'linear-gradient(135deg, #3b82f6, #8b5cf6)',
    'linear-gradient(135deg, #14b8a6, #84cc16)'
  ];

  // Подписи для типов записей.
  const TYPE_LABELS = { login: 'Логин', card: 'Карта', note: 'Заметка' };

  /* ------------------------------ Утилиты ------------------------------- */

  // Возвращает HTML-иконку из SVG-спрайта в popup.html.
  function icon(name) {
    return `<svg aria-hidden="true"><use href="#i-${name}"></use></svg>`;
  }

  // Экранирование перед вставкой в innerHTML — защита от XSS
  // через название записи или заметку.
  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[char]));
  }

  // Простейший хеш строки: одинаковое название → одинаковый цвет аватарки.
  function hashString(value) {
    let hash = 0;
    for (let i = 0; i < String(value).length; i += 1) {
      hash = (hash * 31 + String(value).charCodeAt(i)) >>> 0;
    }
    return hash;
  }

  // CSS-стиль для аватарки записи.
  function avatarStyle(title) {
    return `background: ${GRADIENTS[hashString(title) % GRADIENTS.length]}`;
  }

  // Первая буква названия для аватарки.
  function avatarLetter(title) {
    const clean = String(title || '?').trim();
    return (clean[0] || '?').toUpperCase();
  }

  // Из URL достаём домен: https://www.example.com/login → example.com.
  function hostFromUrl(url) {
    try {
      return new URL(url).hostname.replace(/^www\./, '');
    } catch (error) {
      return '';
    }
  }

  // Красивый короткий вид ссылки для карточки.
  function prettyUrl(url) {
    try {
      const parsed = new URL(url);
      return parsed.hostname.replace(/^www\./, '') + (parsed.pathname !== '/' ? parsed.pathname : '');
    } catch (error) {
      return url;
    }
  }

  // Добавляем https://, если пользователь ввёл сайт без схемы.
  function normalizeUrl(url) {
    if (!url) return '';
    return /^https?:\/\//i.test(url) ? url : `https://${url}`;
  }

  // Дата в формате «5 нояб. 2026 г.».
  function formatDate(iso) {
    if (!iso) return '—';
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleDateString('ru-RU', { day: 'numeric', month: 'short', year: 'numeric' });
  }

  // Русские склонения: 1 запись, 2 записи, 5 записей.
  function plural(count, one, few, many) {
    const mod10 = count % 10;
    const mod100 = count % 100;
    if (mod10 === 1 && mod100 !== 11) return one;
    if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return few;
    return many;
  }

  // Скрываем пароль точками.
  function maskValue(value) {
    const length = Math.min(Math.max(String(value || '').length, 8), 24);
    return '•'.repeat(length);
  }

  // Показываем только последние 4 цифры карты.
  function maskCardNumber(value) {
    const digits = String(value || '').replace(/\s/g, '');
    return `•••• •••• •••• ${digits.slice(-4) || '••••'}`;
  }

  // Всплывающее уведомление внизу окна.
  function toast(message, type = '') {
    const root = $('#toast-root');
    const node = document.createElement('div');
    node.className = `toast ${type}`.trim();
    node.textContent = message;
    root.appendChild(node);
    setTimeout(() => node.remove(), 2600);
  }

  // Главный «мостик» к background. Оборачиваем callback API в Promise.
  // Если background вернул { ok: false }, превращаем это в ошибку,
  // чтобы вызывающий код мог поймать её через try/catch.
  function send(type, payload = {}) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ type, ...payload }, (response) => {
        const error = chrome.runtime.lastError;
        if (error) return reject(new Error(error.message || 'Нет связи с фоновым скриптом'));
        if (!response) return reject(new Error('Пустой ответ фонового скрипта'));
        if (response.ok === false) return reject(new Error(response.error || 'Ошибка'));
        resolve(response);
      });
    });
  }

  // Копирование в буфер обмена + просьба очистить его через N секунд.
  async function copyText(text, label = 'Скопировано') {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch (error) {
      const area = document.createElement('textarea');
      area.value = text;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand('copy');
      } catch (fallbackError) {
        /* ignore */
      }
      area.remove();
    }
    toast(label, 'success');
    try {
      await send('SCHEDULE_CLIPBOARD_CLEAR', {
        seconds: state.settings?.clipboardClearSeconds || 30
      });
    } catch (error) {
      /* не критично */
    }
  }

  /* --- 2. Экраны и состояние ----------------------------------------- */

  // Показываем один из экранов: lock / vault / detail.
  function showScreen(name) {
    $$('.screen').forEach((screen) => {
      screen.hidden = screen.id !== `screen-${name}`;
    });
  }

  // Закрыть модальное окно (редактор, генератор, подтверждение).
  function closeModal() {
    $('#modal-root').innerHTML = '';
  }

  // Открыть сайт записи в новой вкладке.
  function openUrl(url) {
    if (!url) return;
    try {
      chrome.tabs.create({ url: normalizeUrl(url) });
    } catch (error) {
      toast('Не удалось открыть сайт', 'error');
    }
  }

  /* --------------------------- Состояние/экраны -------------------------- */

  // Спросить у background: есть ли хранилище и разблокировано ли оно.
  // От этого зависит, какой экран показать.
  async function refreshState() {
    try {
      const response = await send('GET_STATE');
      state.hasVault = response.hasVault;
      state.unlocked = response.unlocked;
      state.settings = response.settings;
      if (state.unlocked) {
        showScreen('vault');
        await loadEntries();
      } else {
        showLockScreen();
      }
    } catch (error) {
      toast(error.message, 'error');
    }
  }

  // Экран блокировки: либо создание хранилища, либо ввод пароля.
  function showLockScreen() {
    closeModal();
    stopTotp();
    state.currentEntry = null;
    state.currentEntryId = null;
    state.entries = [];
    showScreen('lock');
    const setup = $('#lock-setup');
    const unlock = $('#unlock-form');
    setup.hidden = state.hasVault;
    unlock.hidden = !state.hasVault;
    $('#unlock-error').hidden = true;
    $('#create-error').hidden = true;
    if (state.hasVault) {
      setTimeout(() => {
        const input = $('#master-password');
        if (input) input.focus();
      }, 60);
    }
  }

  // Загрузить записи из background и отрисовать список.
  async function loadEntries() {
    try {
      const response = await send('GET_ENTRIES');
      state.entries = response.entries || [];
      renderEntries();
    } catch (error) {
      state.unlocked = false;
      showLockScreen();
      toast(error.message, 'error');
    }
  }

  /* --- 3. Список записей --------------------------------------------- */

  // Применяем фильтр по типу и поисковую строку.
  function filteredEntries() {
    const query = state.query.trim().toLowerCase();  // поиск без учёта регистра
    return state.entries.filter((entry) => {
      if (state.filter === 'favorite' && !entry.favorite) return false;
      if (['login', 'card', 'note'].includes(state.filter) && entry.type !== state.filter) return false;
      if (!query) return true;
      const haystack = [
        entry.title,
        entry.username,
        entry.url,
        entry.notes,
        entry.card?.number,
        entry.card?.holder,
        entry.totp
      ].join(' ').toLowerCase();
      return haystack.includes(query);
    });
  }

  // Вторая строка карточки: логин, маска карты или начало заметки.
  function entrySubtitle(entry) {
    if (entry.type === 'card') {
      const digits = String(entry.card?.number || '').replace(/\s/g, '');
      return digits ? `•••• ${digits.slice(-4)}` : 'Банковская карта';
    }
    if (entry.type === 'note') {
      const firstLine = String(entry.notes || '').split('\n')[0];
      return firstLine || 'Заметка';
    }
    return entry.username || hostFromUrl(entry.url) || 'Логин';
  }

  // Отрисовка списка. Внутри — только HTML-строки, без обработчиков:
  // клики ловим одним делегированным обработчиком ниже.
  function renderEntries() {
    const list = $('#entries-list');
    const empty = $('#empty-state');
    const entries = filteredEntries();
    const count = state.entries.length;

    $('#vault-count').textContent = count
      ? `${count} ${plural(count, 'запись', 'записи', 'записей')} · зашифровано`
      : 'Хранилище зашифровано';

    if (count === 0) {  // пустое хранилище
      list.innerHTML = '';
      list.hidden = true;
      empty.hidden = false;
      $('#empty-title').textContent = 'Хранилище пусто';
      $('#empty-text').textContent = 'Добавьте первый пароль, карту или заметку — всё будет зашифровано.';
      $('#empty-add').hidden = false;
      return;
    }

    if (entries.length === 0) {  // ничего не найдено по фильтру
      list.innerHTML = '';
      list.hidden = true;
      empty.hidden = false;
      $('#empty-title').textContent = 'Ничего не найдено';
      $('#empty-text').textContent = 'Попробуйте изменить запрос или выбрать другую категорию.';
      $('#empty-add').hidden = true;
      return;
    }

    empty.hidden = true;
    list.hidden = false;
    list.innerHTML = entries.map((entry) => {
      const actions = [];
      if (entry.type === 'login' && entry.username) {
        actions.push(`<button class="mini-btn" data-action="copy-username" title="Скопировать логин">${icon('user')}</button>`);
      }
      if (entry.type === 'login' && entry.password) {
        actions.push(`<button class="mini-btn" data-action="copy-password" title="Скопировать пароль">${icon('key')}</button>`);
      }
      if (entry.type === 'card' && entry.card?.number) {
        actions.push(`<button class="mini-btn" data-action="copy-card" title="Скопировать номер карты">${icon('card')}</button>`);
      }
      if (entry.type === 'note' && entry.notes) {
        actions.push(`<button class="mini-btn" data-action="copy-notes" title="Скопировать заметку">${icon('copy')}</button>`);
      }
      return `
        <div class="entry" role="button" tabindex="0" data-id="${escapeHtml(entry.id)}" aria-label="${escapeHtml(entry.title)}">
          <div class="entry-avatar" style="${avatarStyle(entry.title)}">${escapeHtml(avatarLetter(entry.title))}</div>
          <div class="entry-main">
            <div class="entry-title">
              ${escapeHtml(entry.title)}
              ${entry.favorite ? `<span class="star">★</span>` : ''}
            </div>
            <div class="entry-sub">${escapeHtml(entrySubtitle(entry))}</div>
          </div>
          <div class="entry-actions">${actions.join('')}</div>
        </div>
      `;
    }).join('');
  }

  /* ------------------------------ Детали -------------------------------- */

  /* --- 4. Детальная карточка ----------------------------------------- */

  // Обычная строка «подпись — значение» с кнопкой копирования.
  function detailRow(label, valueHtml, copyField, extraClass = '') {
    return `
      <div class="field-row">
        <div class="content">
          <div class="field-label">${escapeHtml(label)}</div>
          <div class="field-value ${extraClass}">${valueHtml}</div>
        </div>
        ${copyField ? `<button class="copy-btn" data-copy-field="${copyField}" title="Скопировать">${icon('copy')}</button>` : ''}
      </div>
    `;
  }

  // Строка с секретом: пароль, номер карты или CVV.
  // По умолчанию показываем маску, раскрываем по кнопке «глаз».
  function secretRow(label, field, displayValue) {
    return `
      <div class="field-row">
        <div class="content">
          <div class="field-label">${escapeHtml(label)}</div>
          <div class="field-value secret" data-secret="${field}">${escapeHtml(displayValue)}</div>
        </div>
        <button class="copy-btn" data-reveal="${field}" title="Показать/скрыть">${icon('eye')}</button>
        <button class="copy-btn" data-copy-field="${field}" title="Скопировать">${icon('copy')}</button>
      </div>
    `;
  }

  // Полная карточка записи: аватарка, поля, TOTP, заметки.
  function renderDetail(entry) {
    state.currentEntry = entry;
    $('#detail-crumb').textContent = entry.title;
    const favoriteUse = $('#btn-detail-favorite use');  // меняем иконку «звёздочки»
    favoriteUse.setAttribute('href', entry.favorite ? '#i-star-fill' : '#i-star');
    $('#btn-detail-favorite').style.color = entry.favorite ? '#fbbf24' : '';

    const rows = [];
    if (entry.type === 'login') {
      if (entry.url) {
        rows.push(detailRow(
          'Сайт',
          `<a href="#" data-open-url="1" style="color:#c4b5fd">${escapeHtml(prettyUrl(entry.url))}</a>`,
          ''
        ));
      }
      if (entry.username) rows.push(detailRow('Логин', escapeHtml(entry.username), 'username'));
      if (entry.password) rows.push(secretRow('Пароль', 'password', maskValue(entry.password)));
    }

    if (entry.type === 'card') {
      const card = entry.card || {};
      if (card.number) rows.push(secretRow('Номер карты', 'cardNumber', maskCardNumber(card.number)));
      if (card.holder) rows.push(detailRow('Держатель', escapeHtml(card.holder), 'cardHolder'));
      if (card.expiry) rows.push(detailRow('Срок действия', escapeHtml(card.expiry), 'cardExpiry', 'mono'));
      if (card.cvv) rows.push(secretRow('CVV', 'cardCvv', '•••'));
    }

    const notesHtml = entry.notes
      ? `<div class="notes-block">${escapeHtml(entry.notes)}</div>`
      : '';

    const totpHtml = entry.type === 'login' && entry.totp
      ? `
        <div class="totp">
          <div class="totp-info">
            <div class="totp-label">Код 2FA</div>
            <div class="totp-code" id="totp-code">------</div>
            <div class="totp-time" id="totp-time">Генерация…</div>
          </div>
          <div class="totp-ring" id="totp-ring"><span id="totp-seconds">30</span></div>
          <button class="copy-btn" data-copy-totp="1" title="Скопировать код">${icon('copy')}</button>
        </div>
      `
      : '';

    const actions = [];
    if (entry.type === 'login' && entry.password) {
      actions.push(`<button class="btn btn-primary btn-sm" data-fill-page="1">${icon('wand')} Заполнить</button>`);
      actions.push(`<button class="btn btn-ghost btn-sm" data-copy-field="password">${icon('copy')} Пароль</button>`);
    }
    if (entry.url) {
      actions.push(`<button class="btn btn-ghost btn-sm" data-open-url="1">${icon('external')} Открыть сайт</button>`);
    }
    if (entry.type === 'card' && entry.card?.number) {
      actions.push(`<button class="btn btn-primary btn-sm" data-copy-field="cardNumber">${icon('copy')} Номер карты</button>`);
    }

    const age = entry.passwordUpdatedAt ? KeyGuardGenerator.passwordAgeDays(entry.passwordUpdatedAt) : 0;

    $('#detail-body').innerHTML = `
      <div class="detail-hero">
        <div class="detail-avatar" style="${avatarStyle(entry.title)}">${escapeHtml(avatarLetter(entry.title))}</div>
        <h2 class="detail-title">${escapeHtml(entry.title)}</h2>
        <p class="detail-url">${entry.type === 'login' && entry.url ? escapeHtml(hostFromUrl(entry.url)) : escapeHtml(TYPE_LABELS[entry.type])}</p>
        <div class="detail-actions">${actions.join('')}</div>
      </div>
      ${rows.join('')}
      ${totpHtml}
      ${notesHtml}
      <div class="detail-meta">
        <span>Создано: ${formatDate(entry.createdAt)}</span>
        <span>Изменено: ${formatDate(entry.updatedAt)}</span>
        ${age ? `<span>Паролю ${age} ${plural(age, 'день', 'дня', 'дней')}</span>` : ''}
      </div>
    `;

    startTotp(entry);
  }

  // Открыть карточку записи по id.
  function openDetail(id) {
    const entry = state.entries.find((item) => item.id === id);
    if (!entry) return;
    state.currentEntryId = id;
    renderDetail(entry);
    showScreen('detail');
  }

  // Значение поля по имени — нужно для кнопок «Скопировать».
  function getFieldValue(field) {
    const entry = state.currentEntry;
    if (!entry) return '';
    switch (field) {
      case 'username': return entry.username || '';
      case 'password': return entry.password || '';
      case 'cardNumber': return entry.card?.number || '';
      case 'cardHolder': return entry.card?.holder || '';
      case 'cardExpiry': return entry.card?.expiry || '';
      case 'cardCvv': return entry.card?.cvv || '';
      case 'notes': return entry.notes || '';
      case 'totp': return state.currentTotpCode || entry.totp || '';
      default: return '';
    }
  }

  // Показать/скрыть секретное значение.
  function toggleSecret(field, button) {
    const valueNode = $(`[data-secret="${field}"]`);
    if (!valueNode) return;
    const entry = state.currentEntry;
    let real = '';
    if (field === 'password') real = entry.password || '';
    if (field === 'cardNumber') real = entry.card?.number || '';
    if (field === 'cardCvv') real = entry.card?.cvv || '';
    const revealed = valueNode.dataset.revealed === '1';
    if (revealed) {
      valueNode.textContent = field === 'cardNumber' ? maskCardNumber(real) : maskValue(real);
      valueNode.dataset.revealed = '0';
      button.querySelector('use').setAttribute('href', '#i-eye');
    } else {
      valueNode.textContent = field === 'cardNumber' ? real : real;
      valueNode.dataset.revealed = '1';
      button.querySelector('use').setAttribute('href', '#i-eye-off');
    }
  }

  /* ------------------------------- TOTP --------------------------------- */

  /* --- 5. TOTP-код --------------------------------------------------- */

  // Останавливаем таймер, когда уходим с карточки.
  function stopTotp() {
    if (state.totpTimer) clearInterval(state.totpTimer);
    state.totpTimer = null;
    state.currentTotpCode = '';
  }

  // Каждую секунду пересчитываем код и обновляем кружок-таймер.
  function startTotp(entry) {
    stopTotp();
    if (!entry || !entry.totp) return;
    const tick = async () => {
      const codeNode = $('#totp-code');
      if (!codeNode) {
        stopTotp();
        return;
      }
      try {
        const result = await KeyGuardTotp.generateTotp(entry.totp);
        state.currentTotpCode = result.code;
        codeNode.textContent = result.code;
        const timeNode = $('#totp-time');
        if (timeNode) timeNode.textContent = `Обновится через ${result.remaining} с`;
        const ring = $('#totp-ring');
        if (ring) ring.style.setProperty('--progress', String(result.remaining / result.period));
        const seconds = $('#totp-seconds');
        if (seconds) seconds.textContent = result.remaining;
      } catch (error) {
        const timeNode = $('#totp-time');
        if (timeNode) timeNode.textContent = 'Некорректный TOTP-секрет';
      }
    };
    tick();
    state.totpTimer = setInterval(tick, 1000);
  }

  /* ------------------------------ Редактор ------------------------------ */

  /* --- 6. Редактор записи -------------------------------------------- */

  // В редакторе показываем только поля выбранного типа:
  // у карты нет логина/TOTP, у заметки нет пароля.
  function updateTypeVisibility(type) {
    const login = $('#login-fields');
    const card = $('#card-fields');
    if (login) login.hidden = type !== 'login';
    if (card) card.hidden = type !== 'card';
  }

  // Рисуем 4 полоски надёжности и подпись (слабый/надёжный/отличный).
  function paintStrength(container, labelNode, entropyNode, password) {
    if (!container) return;
    const result = KeyGuardGenerator.estimateStrength(password);
    $$('span', container).forEach((span, index) => {
      span.className = index < result.score ? `on-${result.score}` : '';
    });
    if (labelNode) labelNode.textContent = result.label;
    if (entropyNode) entropyNode.textContent = result.entropy ? `≈ ${result.entropy} бит` : '';
    return result;
  }

  // Открыть редактор. entry = null означает «новая запись».
  // prefill используется, когда пароль пришёл из генератора.
  function openEditor(entry = null, prefill = null) {
    closeModal();
    state.editingEntryId = entry?.id || null;  // запоминаем, что редактируем
    const isNew = !entry;
    const data = entry || {
      type: 'login',
      title: '',
      username: '',
      password: prefill?.password || '',
      url: '',
      notes: '',
      card: { number: '', holder: '', expiry: '', cvv: '' },
      totp: '',
      favorite: false
    };
    if (prefill?.password && !entry) data.password = prefill.password;
    const card = data.card || {};

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal-card" role="dialog" aria-modal="true" aria-label="${isNew ? 'Новая запись' : 'Редактирование записи'}">
        <div class="modal-head">
          <h2>${isNew ? 'Новая запись' : 'Редактирование'}</h2>
          <button class="modal-close" data-close aria-label="Закрыть">${icon('x')}</button>
        </div>
        <div class="form-grid">
          <div class="form-row">
            <div>
              <label class="lbl" for="entry-type">Тип записи</label>
              <select class="input" id="entry-type">
                <option value="login" ${data.type === 'login' ? 'selected' : ''}>Логин и пароль</option>
                <option value="card" ${data.type === 'card' ? 'selected' : ''}>Банковская карта</option>
                <option value="note" ${data.type === 'note' ? 'selected' : ''}>Заметка</option>
              </select>
            </div>
            <div>
              <label class="lbl" for="entry-title">Название</label>
              <input class="input" id="entry-title" placeholder="Например, Почта" value="${escapeHtml(data.title)}" />
            </div>
          </div>

          <div id="login-fields">
            <div class="form-row">
              <div>
                <label class="lbl" for="entry-url">Сайт</label>
                <input class="input" id="entry-url" placeholder="https://example.com" value="${escapeHtml(data.url)}" />
              </div>
              <div>
                <label class="lbl" for="entry-username">Логин</label>
                <input class="input" id="entry-username" placeholder="user@example.com" value="${escapeHtml(data.username)}" autocomplete="off" />
              </div>
            </div>
            <div style="margin-top: 10px">
              <label class="lbl" for="entry-password">Пароль</label>
              <div class="field multiple">
                <input id="entry-password" type="password" placeholder="Введите или сгенерируйте" value="${escapeHtml(data.password)}" autocomplete="new-password" />
                <div class="suffix">
                  <button type="button" class="js-toggle-password" data-target="entry-password" aria-label="Показать пароль">${icon('eye')}</button>
                  <button type="button" id="entry-generate" title="Сгенерировать" aria-label="Сгенерировать">${icon('wand')}</button>
                  ${state.settings?.breachCheck !== false ? `<button type="button" id="entry-breach" title="Проверить утечки" aria-label="Проверить утечки">${icon('shield-check')}</button>` : ''}
                </div>
              </div>
              <div class="strength" id="entry-strength"><span></span><span></span><span></span><span></span></div>
              <div class="strength-label"><span id="entry-strength-label">Надёжность</span><span id="entry-entropy"></span></div>
              <div class="hint" id="breach-result" style="margin-top: 6px"></div>
            </div>
            <div style="margin-top: 10px">
              <label class="lbl" for="entry-totp">TOTP-секрет (двухфакторная аутентификация)</label>
              <input class="input" id="entry-totp" placeholder="JBSW Y3DP EHPK 3PXP" value="${escapeHtml(data.totp)}" autocomplete="off" />
            </div>
          </div>

          <div id="card-fields" hidden>
            <div class="form-row">
              <div>
                <label class="lbl" for="card-number">Номер карты</label>
                <input class="input" id="card-number" placeholder="0000 0000 0000 0000" value="${escapeHtml(card.number)}" inputmode="numeric" autocomplete="off" />
              </div>
              <div>
                <label class="lbl" for="card-holder">Держатель</label>
                <input class="input" id="card-holder" placeholder="IVAN IVANOV" value="${escapeHtml(card.holder)}" autocomplete="off" />
              </div>
            </div>
            <div class="form-row" style="margin-top: 10px">
              <div>
                <label class="lbl" for="card-expiry">Срок действия</label>
                <input class="input" id="card-expiry" placeholder="MM/YY" value="${escapeHtml(card.expiry)}" autocomplete="off" />
              </div>
              <div>
                <label class="lbl" for="card-cvv">CVV</label>
                <input class="input" id="card-cvv" type="password" placeholder="•••" value="${escapeHtml(card.cvv)}" inputmode="numeric" autocomplete="off" />
              </div>
            </div>
          </div>

          <div>
            <label class="lbl" for="entry-notes">Заметки</label>
            <textarea class="input" id="entry-notes" rows="3" placeholder="Дополнительная информация">${escapeHtml(data.notes)}</textarea>
          </div>

          <label class="gen-row" style="padding: 0">
            <span class="lbl" style="margin: 0">Добавить в избранное</span>
            <span class="switch">
              <input type="checkbox" id="entry-favorite" ${data.favorite ? 'checked' : ''} />
              <span></span>
            </span>
          </label>
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" data-close>Отмена</button>
          <button class="btn btn-primary" id="entry-save">${icon('check')} Сохранить</button>
        </div>
      </div>
    `;
    $('#modal-root').appendChild(overlay);

    updateTypeVisibility(data.type);
    paintStrength($('#entry-strength'), $('#entry-strength-label'), $('#entry-entropy'), data.password);

    $('#entry-type').addEventListener('change', (event) => updateTypeVisibility(event.target.value));  // при смене типа показываем другие поля
    $('#entry-password').addEventListener('input', (event) => {
      paintStrength($('#entry-strength'), $('#entry-strength-label'), $('#entry-entropy'), event.target.value);
      $('#breach-result').textContent = '';
    });
    $('#entry-generate').addEventListener('click', () => {  // кнопка «сгенерировать пароль»
      const password = KeyGuardGenerator.generatePassword(state.settings?.generator || {});
      $('#entry-password').value = password;
      $('#entry-password').type = 'text';
      const toggle = $('#entry-password')?.parentElement?.querySelector('.js-toggle-password use');
      if (toggle) toggle.setAttribute('href', '#i-eye-off');
      paintStrength($('#entry-strength'), $('#entry-strength-label'), $('#entry-entropy'), password);
      toast('Пароль сгенерирован');
    });
    if ($('#entry-breach')) $('#entry-breach').addEventListener('click', async () => {  // кнопка проверки утечек
      const password = $('#entry-password').value;
      const resultNode = $('#breach-result');
      if (!password) {
        resultNode.textContent = 'Сначала введите пароль';
        return;
      }
      resultNode.textContent = 'Проверяем по базе утечек…';
      try {
        const result = await send('CHECK_BREACH', { password });
        resultNode.textContent = result.breached
          ? `⚠ Пароль найден в утечках ${result.count} раз(а). Смените его!`
          : '✓ Утечек не найдено (по данным Have I Been Pwned)';
        resultNode.style.color = result.breached ? '#fda4af' : '#6ee7b7';
      } catch (error) {
        resultNode.textContent = `Не удалось проверить: ${error.message}`;
        resultNode.style.color = '#fda4af';
      }
    });
    $('#entry-save').addEventListener('click', saveEditor);
    overlay.addEventListener('click', (event) => {
      if (event.target === overlay || event.target.closest('[data-close]')) closeModal();
    });
    setTimeout(() => {
      const title = $('#entry-title');
      if (title) title.focus();
    }, 60);
  }

  // Собрать данные из формы и отправить в background.
  // background сам решит: добавить новую запись или обновить существующую.
  async function saveEditor() {
    const type = $('#entry-type').value;
    const title = $('#entry-title').value.trim();
    if (!title) {
      toast('Введите название записи', 'error');
      $('#entry-title').focus();
      return;
    }
    const existing = state.entries.find((entry) => entry.id === state.editingEntryId);
    const payload = {
      id: existing?.id,
      type,
      title,
      username: type === 'login' ? $('#entry-username').value.trim() : '',
      password: type === 'login' ? $('#entry-password').value : '',
      url: type === 'login' ? $('#entry-url').value.trim() : '',
      notes: $('#entry-notes').value,
      card: type === 'card' ? {
        number: $('#card-number').value.trim(),
        holder: $('#card-holder').value.trim(),
        expiry: $('#card-expiry').value.trim(),
        cvv: $('#card-cvv').value
      } : { number: '', holder: '', expiry: '', cvv: '' },
      totp: type === 'login' ? $('#entry-totp').value.trim().replace(/\s/g, '') : '',
      favorite: $('#entry-favorite').checked
    };

    const button = $('#entry-save');  // блокируем кнопку, чтобы не сохранить дважды
    button.disabled = true;
    try {
      const response = await send('UPSERT_ENTRY', { entry: payload });  // сохраняем через service worker
      state.entries = response.entries;
      closeModal();
      renderEntries();
      if (state.currentEntryId && response.entry?.id === state.currentEntryId) {
        renderDetail(response.entry);
        showScreen('detail');
      } else {
        state.currentEntryId = null;
        showScreen('vault');
      }
      toast(existing ? 'Изменения сохранены' : 'Запись добавлена', 'success');
    } catch (error) {
      toast(error.message, 'error');
      button.disabled = false;
    }
  }

  /* ----------------------------- Генератор ------------------------------ */

  /* --- 7. Генератор паролей ------------------------------------------ */

  // Модальное окно генератора. Настройки берём из state.settings,
  // но меняем только локальную копию — сохраняются они на странице options.
  function openGenerator() {
    closeModal();
    state.generatorOptions = { ...(state.settings?.generator || {}) };
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal-card" role="dialog" aria-modal="true" aria-label="Генератор паролей">
        <div class="modal-head">
          <h2>Генератор паролей</h2>
          <button class="modal-close" data-close aria-label="Закрыть">${icon('x')}</button>
        </div>
        <div class="gen-display">
          <div class="gen-password" id="gen-password"></div>
          <div class="gen-actions">
            <button class="icon-btn" id="gen-refresh" title="Сгенерировать заново" aria-label="Сгенерировать заново">${icon('refresh')}</button>
            <button class="icon-btn" id="gen-copy" title="Скопировать" aria-label="Скопировать">${icon('copy')}</button>
          </div>
        </div>
        <div class="strength" id="gen-strength"><span></span><span></span><span></span><span></span></div>
        <div class="strength-label"><span id="gen-strength-label">Надёжность</span><span id="gen-entropy"></span></div>

        <div style="margin-top: 14px">
          <div class="gen-row">
            <span class="lbl">Длина пароля</span>
            <span class="length-value" id="gen-length-value">20</span>
          </div>
          <input type="range" class="range" id="gen-length" min="8" max="64" value="20" />
        </div>

        <div class="gen-row">
          <span class="lbl">Строчные буквы (a-z)</span>
          <label class="switch"><input type="checkbox" data-gen-option="lower" checked /><span></span></label>
        </div>
        <div class="gen-row">
          <span class="lbl">Заглавные буквы (A-Z)</span>
          <label class="switch"><input type="checkbox" data-gen-option="upper" checked /><span></span></label>
        </div>
        <div class="gen-row">
          <span class="lbl">Цифры (0-9)</span>
          <label class="switch"><input type="checkbox" data-gen-option="digits" checked /><span></span></label>
        </div>
        <div class="gen-row">
          <span class="lbl">Символы (!@#$…)</span>
          <label class="switch"><input type="checkbox" data-gen-option="symbols" checked /><span></span></label>
        </div>
        <div class="gen-row">
          <span class="lbl">Без похожих символов (Il1O0o)</span>
          <label class="switch"><input type="checkbox" data-gen-option="avoidAmbiguous" checked /><span></span></label>
        </div>

        <div class="modal-actions">
          <button class="btn btn-ghost" data-close>Закрыть</button>
          <button class="btn btn-primary" id="gen-use">${icon('plus')} Создать запись</button>
        </div>
      </div>
    `;
    $('#modal-root').appendChild(overlay);

    const lengthInput = $('#gen-length');
    const syncOptions = () => {
      state.generatorOptions.length = Number(lengthInput.value);
      $$('[data-gen-option]').forEach((input) => {
        state.generatorOptions[input.dataset.genOption] = input.checked;
      });
      if (!['lower', 'upper', 'digits', 'symbols'].some((key) => state.generatorOptions[key])) {
        state.generatorOptions.lower = true;
        const lower = $('[data-gen-option="lower"]');
        if (lower) lower.checked = true;
      }
      const percent = ((lengthInput.value - lengthInput.min) / (lengthInput.max - lengthInput.min)) * 100;
      lengthInput.style.setProperty('--fill', `${percent}%`);
      $('#gen-length-value').textContent = lengthInput.value;
    };

    const regenerate = () => {  // пересчитать пароль при любом изменении настроек
      syncOptions();
      state.generatorPassword = KeyGuardGenerator.generatePassword(state.generatorOptions);
      $('#gen-password').textContent = state.generatorPassword;
      paintStrength($('#gen-strength'), $('#gen-strength-label'), $('#gen-entropy'), state.generatorPassword);
    };

    lengthInput.addEventListener('input', regenerate);
    $$('[data-gen-option]').forEach((input) => input.addEventListener('change', regenerate));
    $('#gen-refresh').addEventListener('click', regenerate);
    $('#gen-copy').addEventListener('click', () => copyText(state.generatorPassword, 'Пароль скопирован'));  // копируем сгенерированный пароль
    $('#gen-use').addEventListener('click', () => {  // создать запись с этим паролем
      const password = state.generatorPassword;
      closeModal();
      openEditor(null, { password });
    });
    overlay.addEventListener('click', (event) => {
      if (event.target === overlay || event.target.closest('[data-close]')) closeModal();
    });

    regenerate();
  }

  /* ------------------------------ Подтверждение ------------------------- */

  /* --- 8. Подтверждение и удаление ----------------------------------- */
  function confirmDialog({ title, text, confirmLabel = 'Удалить', onConfirm }) {
    closeModal();
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal-card" role="alertdialog" aria-modal="true" aria-label="${escapeHtml(title)}">
        <div class="modal-head">
          <h2>${escapeHtml(title)}</h2>
          <button class="modal-close" data-close aria-label="Закрыть">${icon('x')}</button>
        </div>
        <p class="hint" style="font-size: 12px; line-height: 1.6">${escapeHtml(text)}</p>
        <div class="modal-actions">
          <button class="btn btn-ghost" data-close>Отмена</button>
          <button class="btn btn-danger" id="confirm-yes">${escapeHtml(confirmLabel)}</button>
        </div>
      </div>
    `;
    $('#modal-root').appendChild(overlay);
    overlay.addEventListener('click', (event) => {
      if (event.target === overlay || event.target.closest('[data-close]')) closeModal();
    });
    $('#confirm-yes').addEventListener('click', async () => {
      const button = $('#confirm-yes');
      button.disabled = true;
      try {
        await onConfirm();
      } catch (error) {
        toast(error.message, 'error');
        button.disabled = false;
      }
    });
  }

  // Удаление записи с подтверждением.
  async function deleteCurrentEntry() {
    const entry = state.currentEntry;
    if (!entry) return;
    confirmDialog({
      title: 'Удалить запись?',
      text: `«${entry.title}» будет удалена из хранилища. Это действие нельзя отменить.`,
      confirmLabel: 'Удалить',
      onConfirm: async () => {
        const response = await send('DELETE_ENTRY', { id: entry.id });
        state.entries = response.entries;
        state.currentEntry = null;
        state.currentEntryId = null;
        closeModal();
        stopTotp();
        renderEntries();
        showScreen('vault');
        toast('Запись удалена');
      }
    });
  }

  /* ------------------------------- События ------------------------------- */

  /* --- 9. Обработчики событий ---------------------------------------- */

  // Здесь собраны все клики и формы. Логика вынесена в функции выше,
  // поэтому обработчики короткие и их легко читать.
  function bindEvents() {
    $('#unlock-form').addEventListener('submit', async (event) => {  // вход по мастер-паролю
      event.preventDefault();
      const password = $('#master-password').value;
      const errorNode = $('#unlock-error');
      errorNode.hidden = true;
      const button = $('#unlock-form button[type="submit"]');
      button.disabled = true;
      try {
        const response = await send('UNLOCK', { password });
        state.hasVault = response.hasVault;
        state.unlocked = response.unlocked;
        state.settings = response.settings;
        $('#master-password').value = '';
        showScreen('vault');
        await loadEntries();
        toast('Хранилище разблокировано', 'success');
      } catch (error) {
        errorNode.textContent = error.message;
        errorNode.hidden = false;
        $('#unlock-form').classList.add('shake');
        setTimeout(() => $('#unlock-form').classList.remove('shake'), 400);
        $('#master-password').select();
      } finally {
        button.disabled = false;
      }
    });

    $('#create-form').addEventListener('submit', async (event) => {  // создание нового хранилища
      event.preventDefault();
      const password = $('#new-password').value;
      const confirm = $('#new-password-confirm').value;
      const errorNode = $('#create-error');
      errorNode.hidden = true;
      if (password.length < 8) {
        errorNode.textContent = 'Мастер-пароль должен быть не короче 8 символов';
        errorNode.hidden = false;
        return;
      }
      if (password !== confirm) {
        errorNode.textContent = 'Пароли не совпадают';
        errorNode.hidden = false;
        return;
      }
      const strength = KeyGuardGenerator.estimateStrength(password);
      if (strength.score < 2) {
        errorNode.textContent = 'Слишком простой пароль. Добавьте заглавные буквы, цифры или символы.';
        errorNode.hidden = false;
        return;
      }
      const button = $('#create-form button[type="submit"]');
      button.disabled = true;
      try {
        await send('CREATE_VAULT', { password });
        state.hasVault = true;
        state.unlocked = true;
        $('#new-password').value = '';
        $('#new-password-confirm').value = '';
        showScreen('vault');
        await loadEntries();
        toast('Хранилище создано. Сохраните мастер-пароль!', 'success');
      } catch (error) {
        errorNode.textContent = error.message;
        errorNode.hidden = false;
      } finally {
        button.disabled = false;
      }
    });

    $$('[data-toggle-password]').forEach((button) => {
      button.addEventListener('click', () => {
        const input = document.getElementById(button.dataset.togglePassword);
        if (!input) return;
        const showing = input.type === 'text';
        input.type = showing ? 'password' : 'text';
        button.querySelector('use').setAttribute('href', showing ? '#i-eye' : '#i-eye-off');
      });
    });

    $('#new-password').addEventListener('input', (event) => {
      paintStrength($('#new-strength'), $('#new-strength-label'), $('#new-entropy'), event.target.value);
    });

    $('#filter-chips').addEventListener('click', (event) => {  // переключение категорий
      const chip = event.target.closest('[data-filter]');
      if (!chip) return;
      state.filter = chip.dataset.filter;
      $$('#filter-chips .chip').forEach((item) => item.classList.toggle('active', item === chip));
      renderEntries();
    });

    let searchTimer = null;
    $('#search-input').addEventListener('input', (event) => {
      clearTimeout(searchTimer);
      const value = event.target.value;
      searchTimer = setTimeout(() => {
        state.query = value;
        renderEntries();
      }, 120);
    });

    $('#entries-list').addEventListener('click', async (event) => {  // клик по записи или по кнопке копирования
      const actionButton = event.target.closest('[data-action]');
      const entryNode = event.target.closest('.entry');
      if (!entryNode) return;
      const entry = state.entries.find((item) => item.id === entryNode.dataset.id);
      if (!entry) return;
      if (actionButton) {
        event.stopPropagation();
        const action = actionButton.dataset.action;
        if (action === 'copy-username') await copyText(entry.username, 'Логин скопирован');
        if (action === 'copy-password') await copyText(entry.password, 'Пароль скопирован');
        if (action === 'copy-card') await copyText(entry.card?.number || '', 'Номер карты скопирован');
        if (action === 'copy-notes') await copyText(entry.notes, 'Заметка скопирована');
        return;
      }
      openDetail(entry.id);
    });

    $('#entries-list').addEventListener('keydown', (event) => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      const entryNode = event.target.closest('.entry');
      if (!entryNode) return;
      event.preventDefault();
      openDetail(entryNode.dataset.id);
    });

    $('#btn-add').addEventListener('click', () => openEditor());  // новая запись
    $('#empty-add').addEventListener('click', () => openEditor());
    $('#btn-generator').addEventListener('click', openGenerator);
    $('#btn-options').addEventListener('click', () => chrome.runtime.openOptionsPage());
    $('#btn-lock').addEventListener('click', async () => {  // заблокировать хранилище
      await send('LOCK');
      state.unlocked = false;
      state.entries = [];
      showLockScreen();
      toast('Хранилище заблокировано');
    });

    $('#btn-detail-back').addEventListener('click', () => {
      stopTotp();
      state.currentEntryId = null;
      state.currentEntry = null;
      renderEntries();
      showScreen('vault');
    });
    $('#btn-detail-edit').addEventListener('click', () => {
      if (state.currentEntry) openEditor(state.currentEntry);
    });
    $('#btn-detail-delete').addEventListener('click', deleteCurrentEntry);  // удалить запись
    $('#btn-detail-favorite').addEventListener('click', async () => {
      if (!state.currentEntry) return;
      try {
        const response = await send('TOGGLE_FAVORITE', { id: state.currentEntry.id });
        state.entries = response.entries;
        const updated = state.entries.find((entry) => entry.id === state.currentEntry.id);
        if (updated) renderDetail(updated);
        renderEntries();
      } catch (error) {
        toast(error.message, 'error');
      }
    });

    $('#detail-body').addEventListener('click', async (event) => {  // копирование и раскрытие полей
      const copyButton = event.target.closest('[data-copy-field]');
      if (copyButton) {
        const value = getFieldValue(copyButton.dataset.copyField);
        const labels = {
          username: 'Логин скопирован',
          password: 'Пароль скопирован',
          cardNumber: 'Номер карты скопирован',
          cardHolder: 'Имя владельца скопировано',
          cardExpiry: 'Срок действия скопирован',
          cardCvv: 'CVV скопирован'
        };
        await copyText(value, labels[copyButton.dataset.copyField] || 'Скопировано');
        return;
      }
      const revealButton = event.target.closest('[data-reveal]');
      if (revealButton) {
        toggleSecret(revealButton.dataset.reveal, revealButton);
        return;
      }
      if (event.target.closest('[data-fill-page]')) {
        const entry = state.currentEntry;
        if (!entry) return;
        try {
          const response = await send('FILL_ON_PAGE', { entryId: entry.id });
          if (response.filled) toast('Логин и пароль подставлены на странице', 'success');
          else toast('Не удалось заполнить форму на этой странице', 'error');
        } catch (error) {
          toast(error.message, 'error');
        }
        return;
      }
      if (event.target.closest('[data-open-url]')) {
        event.preventDefault();
        openUrl(state.currentEntry?.url);
        return;
      }
      if (event.target.closest('[data-copy-totp]')) {
        await copyText(state.currentTotpCode, 'Код 2FA скопирован');
      }
    });

    $('#modal-root').addEventListener('click', (event) => {
      if (event.target.id === 'modal-root' || event.target.classList.contains('modal-overlay')) {
        closeModal();
      }
    });

    document.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        if (state.unlocked) $('#search-input').focus();
      }
      if (event.key === 'Escape') {
        if ($('#modal-root').children.length) closeModal();
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'l') {
        event.preventDefault();
        if (state.unlocked) $('#btn-lock').click();
      }
    });

    document.addEventListener('pointerdown', touchActivity, true);
    document.addEventListener('keydown', touchActivity, true);

    chrome.runtime.onMessage.addListener((message) => {
      if (message?.type === 'KEYGUARD_LOCKED') {
        state.unlocked = false;
        state.entries = [];
        closeModal();
        showLockScreen();
        toast('Хранилище заблокировано');
      }
    });

    window.addEventListener('focus', () => {
      if (!state.unlocked || $('#modal-root').children.length) return;
      refreshState();
    });
  }

  /* --- 10. Активность и запуск --------------------------------------- */

  // Сообщаем background, что пользователь активен. Не чаще раза в 4 секунды,
  // чтобы не заваливать service worker сообщениями.
  function touchActivity() {
    const now = Date.now();
    if (now - state.lastTouch < 4000) return;
    state.lastTouch = now;
    if (!state.unlocked) return;
    send('PING', { touch: true }).catch(() => {});
  }

  // Точка входа: подписываемся на события и загружаем состояние.
  function init() {
    bindEvents();
    refreshState();
    setInterval(() => {  // раз в 20 секунд проверяем, не заблокировалось ли хранилище
      if (state.unlocked) send('PING').catch(() => {});
    }, 20000);
  }

  // Стартуем после того, как DOM загрузился (скрипт подключён в конце body).
  init();
})();
