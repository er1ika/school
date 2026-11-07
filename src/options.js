/**
 * KeyGuard Options — страница настроек, аудита и резервных копий.
 */
(() => {
  'use strict';

  /* =====================================================================
     КАК ЧИТАТЬ ЭТОТ ФАЙЛ
     ---------------------------------------------------------------------
     options.js — страница настроек, которая открывается в отдельной вкладке.
     1. Утилиты и общение с background.
     2. Вкладки и состояние (разблокировано / заблокировано).
     3. Безопасность: автоблокировка, буфер обмена, смена мастер-пароля.
     4. Генератор: настройки по умолчанию и превью пароля.
     5. Аудит: слабые, повторные и старые пароли.
     6. Данные: экспорт, импорт и удаление хранилища.

     Страница не хранит пароли: она просит записи у background,
     анализирует их в памяти и забывает при закрытии.
     ===================================================================== */

  /* --- 1. Утилиты ---------------------------------------------------- */

  // $ и $$ — короткие обёртки для поиска элементов.
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

  // Состояние страницы: есть ли хранилище, разблокировано ли,
  // какие настройки загружены и какой файл ждёт импорта.
  const state = {
    hasVault: false,
    unlocked: false,
    settings: null,  // настройки из background
    generatorOptions: null,  // текущие настройки генератора
    pendingImport: null  // резервная копия, ожидающая пароль
  };

  // Цвета аватарок — те же, что в попапе, чтобы аудит выглядел знакомо.
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

  // Значения генератора по умолчанию (если настройки ещё не сохранены).
  const DEFAULT_GENERATOR = {
    length: 20,
    lower: true,
    upper: true,
    digits: true,
    symbols: true,
    avoidAmbiguous: true
  };

  /* ------------------------------ Утилиты ------------------------------- */

  // Экранирование перед вставкой в innerHTML.
  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[char]));
  }

  // Хеш строки → стабильный цвет аватарки.
  function hashString(value) {
    let hash = 0;
    for (let i = 0; i < String(value).length; i += 1) {
      hash = (hash * 31 + String(value).charCodeAt(i)) >>> 0;
    }
    return hash;
  }

  // CSS для аватарки.
  function avatarStyle(title) {
    return `background: ${GRADIENTS[hashString(title) % GRADIENTS.length]}`;
  }

  // Первая буква названия.
  function avatarLetter(title) {
    return (String(title || '?').trim()[0] || '?').toUpperCase();
  }

  // Уведомление внизу страницы.
  function toast(message, type = '') {
    const node = document.createElement('div');
    node.className = `toast ${type}`.trim();
    node.textContent = message;
    $('#toast-root').appendChild(node);
    setTimeout(() => node.remove(), 2800);
  }

  // Мостик к background: callback → Promise, ошибки → throw.
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

  // Копирование в буфер и планирование его очистки.
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
      /* ignore */
    }
  }

  // Закрыть модальное окно.
  function closeModal() {
    $('#modal-root').innerHTML = '';
  }

  // Открыть модальное окно с произвольным HTML.
  // Возвращаем overlay, чтобы вызывающий код мог навесить обработчики.
  function openModal(contentHtml) {
    closeModal();
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.style.alignItems = 'center';
    overlay.innerHTML = `
      <div class="modal-card" style="max-width: 460px; width: calc(100% - 32px); border-radius: 20px">
        ${contentHtml}
      </div>
    `;
    $('#modal-root').appendChild(overlay);
    overlay.addEventListener('click', (event) => {
      if (event.target === overlay || event.target.closest('[data-close]')) closeModal();
    });
    return overlay;
  }

  /* ------------------------------ Вкладки ------------------------------- */

  /* --- 2. Вкладки и состояние ---------------------------------------- */

  // Переключение разделов: Безопасность / Генератор / Аудит / Данные / О проекте.
  function initTabs() {
    $$('.nav [data-tab]').forEach((button) => {
      button.addEventListener('click', () => {
        const tab = button.dataset.tab;
        $$('.nav [data-tab]').forEach((item) => item.classList.toggle('active', item === button));
        $$('.panel').forEach((panel) => panel.classList.toggle('active', panel.id === `panel-${tab}`));
        if (tab === 'audit' && state.unlocked) loadAudit();
      });
    });
  }

  /* ------------------------------ Состояние ----------------------------- */

  // Узнаём у background, разблокировано ли хранилище,
  // и обновляем интерфейс под это состояние.
  async function refreshState() {
    try {
      const response = await send('GET_STATE');
      state.hasVault = response.hasVault;
      state.unlocked = response.unlocked;
      state.settings = response.settings;
      applyState();
      if (state.unlocked) {
        await loadAudit();
      } else {
        clearAudit();
      }
    } catch (error) {
      toast(error.message, 'error');
    }
  }

  // Показываем плашку статуса и баннер «хранилище заблокировано».
  // Если хранилище закрыто, форма смены пароля отключается.
  function applyState() {
    const pill = $('#status-pill');
    const text = $('#status-text');
    pill.classList.toggle('locked', !state.unlocked);
    if (!state.hasVault) {
      text.textContent = 'Хранилище не создано';
    } else if (state.unlocked) {
      text.textContent = 'Разблокировано';
    } else {
      text.textContent = 'Заблокировано';
    }

    const banner = $('#locked-banner');  // баннер для заблокированного состояния
    banner.hidden = state.unlocked;
    if (!state.hasVault) {
      $('#locked-banner-text').textContent =
        'Хранилище ещё не создано. Откройте попап KeyGuard и придумайте мастер-пароль.';
    } else {
      $('#locked-banner-text').textContent =
        'Хранилище заблокировано. Откройте попап KeyGuard и введите мастер-пароль.';
    }

    const form = $('#change-password-form');
    $$('input, button', form).forEach((element) => {
      element.disabled = !state.unlocked;
    });
    if (!state.unlocked) {
      $('#change-success').hidden = true;
      $('#change-error').hidden = true;
    }

    applySettingsToControls();
  }

  // Переносим настройки из state в элементы управления.
  function applySettingsToControls() {
    const settings = state.settings;
    if (!settings) return;
    $('#auto-lock').value = String(settings.autoLockMinutes);
    $('#lock-on-idle').checked = Boolean(settings.lockOnIdle);
    $('#clipboard-clear').value = String(settings.clipboardClearSeconds);
    $('#breach-check').checked = settings.breachCheck !== false;
    if (!state.generatorOptions) {
      state.generatorOptions = { ...DEFAULT_GENERATOR, ...(settings.generator || {}) };
    }
    syncGeneratorControls();
    generatePreview();
  }

  /* --------------------------- Настройки безопасности -------------------- */

  /* --- 3. Безопасность ----------------------------------------------- */

  // Сохраняем только изменённые поля, остальные не трогаем.
  async function saveSettings(partial) {
    try {
      const response = await send('SET_SETTINGS', { settings: partial });
      state.settings = response.settings;
      toast('Настройки сохранены', 'success');
    } catch (error) {
      toast(error.message, 'error');
    }
  }

  // Подписки на все элементы раздела «Безопасность».
  function initSecurity() {
    $('#auto-lock').addEventListener('change', (event) => {  // автоблокировка по таймеру
      saveSettings({ autoLockMinutes: Number(event.target.value) });
    });
    $('#lock-on-idle').addEventListener('change', (event) => {  // блокировка при простое системы
      saveSettings({ lockOnIdle: event.target.checked });
    });
    $('#clipboard-clear').addEventListener('change', (event) => {  // очистка буфера обмена
      saveSettings({ clipboardClearSeconds: Number(event.target.value) });
    });
    $('#breach-check').addEventListener('change', (event) => {
      saveSettings({ breachCheck: event.target.checked });
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
      paintStrength(
        $('#change-strength'),
        $('#change-strength-label'),
        $('#change-entropy'),
        event.target.value
      );
    });

    $('#change-password-form').addEventListener('submit', async (event) => {  // смена мастер-пароля
      event.preventDefault();
      const current = $('#current-password').value;
      const next = $('#new-password').value;
      const confirm = $('#new-password-confirm').value;
      const errorNode = $('#change-error');
      const successNode = $('#change-success');
      errorNode.hidden = true;
      successNode.hidden = true;

      if (!state.unlocked) {
        errorNode.textContent = 'Сначала разблокируйте хранилище';
        errorNode.hidden = false;
        return;
      }
      if (next.length < 8) {
        errorNode.textContent = 'Новый пароль должен быть не короче 8 символов';
        errorNode.hidden = false;
        return;
      }
      if (next !== confirm) {
        errorNode.textContent = 'Новые пароли не совпадают';
        errorNode.hidden = false;
        return;
      }
      const strength = KeyGuardGenerator.estimateStrength(next);
      if (strength.score < 2) {
        errorNode.textContent = 'Слишком простой пароль. Используйте заглавные буквы, цифры и символы.';
        errorNode.hidden = false;
        return;
      }

      const button = $('#change-submit');
      button.disabled = true;
      try {
        await send('CHANGE_MASTER_PASSWORD', { currentPassword: current, newPassword: next });  // background перешифрует всё хранилище
        $('#current-password').value = '';
        $('#new-password').value = '';
        $('#new-password-confirm').value = '';
        paintStrength($('#change-strength'), $('#change-strength-label'), $('#change-entropy'), '');
        successNode.textContent = 'Мастер-пароль изменён, хранилище перешифровано.';
        successNode.hidden = false;
        toast('Мастер-пароль обновлён', 'success');
      } catch (error) {
        errorNode.textContent = error.message;
        errorNode.hidden = false;
      } finally {
        button.disabled = false;
      }
    });
  }

  // Полоски надёжности нового пароля.
  function paintStrength(container, labelNode, entropyNode, password) {
    if (!container) return;
    const result = KeyGuardGenerator.estimateStrength(password);
    $$('span', container).forEach((span, index) => {
      span.className = index < result.score ? `on-${result.score}` : '';
    });
    if (labelNode) labelNode.textContent = result.label;
    if (entropyNode) entropyNode.textContent = result.entropy ? `≈ ${result.entropy} бит` : '';
  }

  /* ------------------------------ Генератор ----------------------------- */

  /* --- 4. Генератор -------------------------------------------------- */

  // Записываем значения из state в элементы формы.
  function syncGeneratorControls() {
    const options = state.generatorOptions;
    if (!options) return;
    $('#options-gen-length').value = String(options.length);
    $('#options-gen-length-value').textContent = String(options.length);
    const percent = ((options.length - 8) / (64 - 8)) * 100;
    $('#options-gen-length').style.setProperty('--fill', `${percent}%`);
    $('#gen-lower').checked = Boolean(options.lower);
    $('#gen-upper').checked = Boolean(options.upper);
    $('#gen-digits').checked = Boolean(options.digits);
    $('#gen-symbols').checked = Boolean(options.symbols);
    $('#gen-ambiguous').checked = Boolean(options.avoidAmbiguous);
  }

  // Читаем значения из формы обратно в state.
  function readGeneratorControls() {
    state.generatorOptions = {
      length: Number($('#options-gen-length').value),
      lower: $('#gen-lower').checked,
      upper: $('#gen-upper').checked,
      digits: $('#gen-digits').checked,
      symbols: $('#gen-symbols').checked,
      avoidAmbiguous: $('#gen-ambiguous').checked
    };
    if (!['lower', 'upper', 'digits', 'symbols'].some((key) => state.generatorOptions[key])) {
      state.generatorOptions.lower = true;
      $('#gen-lower').checked = true;
    }
    const percent = ((state.generatorOptions.length - 8) / (64 - 8)) * 100;
    $('#options-gen-length').style.setProperty('--fill', `${percent}%`);
    $('#options-gen-length-value').textContent = String(state.generatorOptions.length);
  }

  // Показываем пример пароля с текущими настройками.
  function generatePreview() {
    if (!state.generatorOptions) return;
    const password = KeyGuardGenerator.generatePassword(state.generatorOptions);
    $('#options-gen-password').textContent = password;
    paintStrength(
      $('#options-gen-strength'),
      $('#options-gen-label'),
      $('#options-gen-entropy'),
      password
    );
    return password;
  }

  // Подписки на изменения в разделе «Генератор».
  function initGenerator() {
    const regenerate = () => {
      readGeneratorControls();
      generatePreview();
    };
    $('#options-gen-length').addEventListener('input', regenerate);
    ['#gen-lower', '#gen-upper', '#gen-digits', '#gen-symbols', '#gen-ambiguous'].forEach((selector) => {
      $(selector).addEventListener('change', regenerate);
    });
    $('#options-gen-refresh').addEventListener('click', regenerate);
    $('#options-gen-copy').addEventListener('click', () => {
      copyText($('#options-gen-password').textContent, 'Пароль скопирован');
    });
    $('#options-gen-save').addEventListener('click', async () => {  // сохраняем настройки генератора в background
      readGeneratorControls();
      await saveSettings({ generator: state.generatorOptions });
    });
    $('#options-gen-reset').addEventListener('click', () => {
      state.generatorOptions = { ...DEFAULT_GENERATOR };
      syncGeneratorControls();
      generatePreview();
      toast('Настройки генератора сброшены');
    });
  }

  /* -------------------------------- Аудит -------------------------------- */

  /* --- 5. Аудит паролей ---------------------------------------------- */

  // Сбрасываем результаты, если хранилище заблокировано или пустое.
  function clearAudit() {
    $('#stat-weak').textContent = '0';
    $('#stat-reused').textContent = '0';
    $('#stat-old').textContent = '0';
    $('#badge-weak').textContent = '0';
    $('#badge-reused').textContent = '0';
    $('#badge-old').textContent = '0';
    const message = state.hasVault
      ? '<p class="hint">Разблокируйте хранилище, чтобы увидеть результаты проверки.</p>'
      : '<p class="hint">Сначала создайте хранилище в попапе KeyGuard.</p>';
    $('#list-weak').innerHTML = message;
    $('#list-reused').innerHTML = '';
    $('#list-old').innerHTML = '';
  }

  // Одна строка результата: аватарка, название и причина.
  function auditItem(entry, reason) {
    return `
      <div class="audit-item">
        <div class="entry-avatar" style="${avatarStyle(entry.title)}">${escapeHtml(avatarLetter(entry.title))}</div>
        <div class="name">${escapeHtml(entry.title)}</div>
        <div class="reason">${escapeHtml(reason)}</div>
      </div>
    `;
  }

  // Рисуем список находок или текст «всё хорошо».
  function renderAuditList(selector, entries, reasonFn, emptyText) {
    const node = $(selector);
    if (!entries.length) {
      node.innerHTML = `<p class="hint">${emptyText}</p>`;
      return;
    }
    node.innerHTML = entries
      .slice(0, 25)
      .map((entry) => auditItem(entry, reasonFn(entry)))
      .join('') + (entries.length > 25 ? `<p class="hint">и ещё ${entries.length - 25}…</p>` : '');
  }

  // Главная функция аудита:
  // 1) берём все логины с паролями;
  // 2) считаем слабые (оценка 0–1 или популярный пароль);
  // 3) группируем по значению пароля, чтобы найти повторы;
  // 4) ищем пароли старше 180 дней.
  async function loadAudit() {
    try {
      const response = await send('GET_ENTRIES');
      const entries = response.entries || [];
      const logins = entries.filter((entry) => entry.type === 'login' && entry.password);

      const weak = [];
      const old = [];
      const groups = new Map();  // пароль → список записей с таким паролем

      for (const entry of logins) {
        const strength = KeyGuardGenerator.estimateStrength(entry.password);
        if (strength.score <= 1 || KeyGuardGenerator.isCommonPassword(entry.password)) {
          weak.push({ entry, reason: strength.label });
        }
        const age = KeyGuardGenerator.passwordAgeDays(entry.passwordUpdatedAt);
        if (age > 180) old.push({ entry, reason: `${age} дней` });  // порог «устаревшего» пароля — 180 дней
        const key = entry.password;
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(entry);
      }

      const reused = [];
      for (const group of groups.values()) {
        if (group.length > 1) {
          for (const entry of group) {
            reused.push({ entry, reason: `пароль у ${group.length} записей` });
          }
        }
      }

      $('#stat-weak').textContent = String(weak.length);
      $('#stat-reused').textContent = String(reused.length);
      $('#stat-old').textContent = String(old.length);
      $('#badge-weak').textContent = String(weak.length);
      $('#badge-reused').textContent = String(reused.length);
      $('#badge-old').textContent = String(old.length);

      renderAuditList('#list-weak', weak.map((item) => item.entry), (entry) => {
        return weak.find((item) => item.entry.id === entry.id)?.reason || '';
      }, 'Слабых паролей не найдено — отличная работа!');
      renderAuditList('#list-reused', reused.map((item) => item.entry), (entry) => {
        return reused.find((item) => item.entry.id === entry.id)?.reason || '';
      }, 'Повторно используемых паролей нет.');
      renderAuditList('#list-old', old.map((item) => item.entry), (entry) => {
        return old.find((item) => item.entry.id === entry.id)?.reason || '';
      }, 'Все пароли менялись недавно.');
    } catch (error) {
      clearAudit();
      if (!/разблокир/i.test(error.message)) toast(error.message, 'error');
    }
  }

  /* ----------------------------- Резервные копии ------------------------- */

  /* --- 6. Данные: экспорт, импорт, сброс ----------------------------- */

  // Скачиваем зашифрованный конверт как JSON-файл.
  // В нём нет открытых паролей — только шифротекст.
  function downloadBackup() {
    if (!state.unlocked) {
      toast('Сначала разблокируйте хранилище', 'error');
      return;
    }
    send('EXPORT_BACKUP')
      .then((response) => {
        const data = JSON.stringify(response.record, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `keyguard-backup-${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1500);
        toast('Зашифрованная копия скачана', 'success');
      })
      .catch((error) => toast(error.message, 'error'));
  }

  // Импорт: просим мастер-пароль от копии и заменяем хранилище.
  function openImportModal(fileName) {
    openModal(`
      <div class="modal-head">
        <h2>Импорт резервной копии</h2>
        <button class="modal-close" data-close aria-label="Закрыть">×</button>
      </div>
      <p class="hint" style="margin-bottom: 12px">Файл: ${escapeHtml(fileName)}. Введите мастер-пароль, который использовался при создании копии.</p>
      <label class="lbl" for="import-password">Мастер-пароль копии</label>
      <div class="field">
        <input id="import-password" type="password" placeholder="Мастер-пароль" autocomplete="off" />
        <div class="suffix"><button type="button" id="import-toggle" aria-label="Показать пароль">👁</button></div>
      </div>
      <p class="error" id="import-error" hidden></p>
      <div class="modal-actions">
        <button class="btn btn-ghost" data-close>Отмена</button>
        <button class="btn btn-primary" id="import-submit">Импортировать</button>
      </div>
    `);
    $('#import-toggle').addEventListener('click', () => {
      const input = $('#import-password');
      input.type = input.type === 'password' ? 'text' : 'password';
    });
    $('#import-submit').addEventListener('click', async () => {
      const password = $('#import-password').value;
      const errorNode = $('#import-error');
      errorNode.hidden = true;
      if (!password) {
        errorNode.textContent = 'Введите мастер-пароль';
        errorNode.hidden = false;
        return;
      }
      const button = $('#import-submit');
      button.disabled = true;
      try {
        await send('IMPORT_BACKUP', { record: state.pendingImport, password });
        closeModal();
        state.unlocked = true;
        state.hasVault = true;
        await refreshState();
        toast('Хранилище импортировано', 'success');
      } catch (error) {
        errorNode.textContent = error.message;
        errorNode.hidden = false;
        button.disabled = false;
      }
    });
    setTimeout(() => {
      const input = $('#import-password');
      if (input) input.focus();
    }, 80);
  }

  // Подписки на кнопки раздела «Данные».
  function initData() {
    $('#btn-export').addEventListener('click', downloadBackup);
    $('#import-file').addEventListener('change', async (event) => {
      const file = event.target.files?.[0];
      event.target.value = '';
      if (!file) return;
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        const record = parsed?.vault || parsed;
        if (!record || !record.salt || !record.verifier || !record.data) {
          throw new Error('Это не резервная копия KeyGuard');
        }
        state.pendingImport = record;
        $('#import-file-name').textContent = `Выбран файл: ${file.name}`;
        openImportModal(file.name);
      } catch (error) {
        toast(error.message, 'error');
      }
    });

    $('#btn-reset').addEventListener('click', () => {  // удаление хранилища с подтверждением словом УДАЛИТЬ
      openModal(`
        <div class="modal-head">
          <h2>Удалить хранилище?</h2>
          <button class="modal-close" data-close aria-label="Закрыть">×</button>
        </div>
        <p class="hint" style="line-height: 1.6; margin-bottom: 12px">
          Будут удалены все записи, настройки и ключ шифрования. Отменить это действие невозможно.
          Если вы просто забыли мастер-пароль, удаление — единственный способ начать заново.
        </p>
        <label class="lbl" for="reset-confirm">Введите слово УДАЛИТЬ для подтверждения</label>
        <input class="input" id="reset-confirm" placeholder="УДАЛИТЬ" autocomplete="off" />
        <div class="modal-actions">
          <button class="btn btn-ghost" data-close>Отмена</button>
          <button class="btn btn-danger" id="reset-yes" disabled>Удалить навсегда</button>
        </div>
      `);
      const input = $('#reset-confirm');
      const button = $('#reset-yes');
      input.addEventListener('input', () => {
        button.disabled = input.value.trim().toUpperCase() !== 'УДАЛИТЬ';
      });
      button.addEventListener('click', async () => {
        button.disabled = true;
        try {
          await send('RESET_VAULT');
          state.hasVault = false;
          state.unlocked = false;
          closeModal();
          await refreshState();
          toast('Хранилище удалено');
        } catch (error) {
          toast(error.message, 'error');
          button.disabled = false;
        }
      });
      setTimeout(() => {
        if (input.isConnected) input.focus();
      }, 80);
    });
  }

  /* ------------------------------- Служебное ----------------------------- */

  /* --- 7. Служебное и запуск ----------------------------------------- */

  // Пробуем открыть попап из вкладки настроек.
  // Chrome разрешает это не всегда — тогда подсказываем нажать на иконку.
  async function openPopup() {
    try {
      if (chrome.action?.openPopup) {
        await chrome.action.openPopup();
        return;
      }
      throw new Error('openPopup недоступен');
    } catch (error) {
      toast('Нажмите на иконку KeyGuard на панели браузера', 'error');
    }
  }

  // Точка входа страницы настроек.
  function init() {
    initTabs();
    initSecurity();
    initGenerator();
    initData();

    $('#btn-open-popup').addEventListener('click', openPopup);
    $('#btn-banner-popup').addEventListener('click', openPopup);
    $('#btn-lock').addEventListener('click', async () => {
      try {
        await send('LOCK');
        await refreshState();
        toast('Хранилище заблокировано');
      } catch (error) {
        toast(error.message, 'error');
      }
    });
    $('#audit-refresh').addEventListener('click', () => {
      if (state.unlocked) loadAudit();
      else toast('Сначала разблокируйте хранилище', 'error');
    });

    chrome.runtime.onMessage.addListener((message) => {
      if (message?.type === 'KEYGUARD_LOCKED' || message?.type === 'KEYGUARD_UNLOCKED') {
        refreshState();
      }
    });

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeModal();
    });

    refreshState();
  }

  init();
})();
