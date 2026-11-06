/**
 * KeyGuard Content Script — работает на страницах сайтов.
 * Не читает пароли без действия пользователя: только заполняет форму по
 * явному запросу и предлагает сохранить пароль после отправки формы.
 */
(() => {
  'use strict';

  if (window.__keyguardContentLoaded) return;
  window.__keyguardContentLoaded = true;

  const SHADOW_HOST_ID = '__keyguard_host__';
  let shadowHost = null;
  let shadowRoot = null;
  let promptNode = null;
  let toastNode = null;
  let pendingCredentials = null;
  let pendingExistingId = null;
  let toastTimer = null;
  let changeTimer = null;
  const lastSent = new Map();

  /* ---------------------------- DOM helpers ---------------------------- */

  function isVisible(element) {
    if (!(element instanceof HTMLElement)) return false;
    const rect = element.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return false;
    const style = getComputedStyle(element);
    return style.visibility !== 'hidden' && style.display !== 'none' && style.opacity !== '0';
  }

  function setNativeValue(element, value) {
    const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (descriptor && descriptor.set) descriptor.set.call(element, value);
    else element.value = value;
    element.dispatchEvent(new Event('input', { bubbles: true }));
    element.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function findPasswordField() {
    const fields = [...document.querySelectorAll('input[type="password"]')].filter(isVisible);
    if (fields.length === 0) return null;
    const inForm = fields.find((field) => field.closest('form'));
    return inForm || fields[0];
  }

  function findUsernameField(passwordField) {
    const form = passwordField?.closest('form');
    const scope = form || document;
    const candidates = [...scope.querySelectorAll('input')].filter((input) => {
      if (!isVisible(input)) return false;
      if (input === passwordField) return false;
      if (input.type === 'password' || input.type === 'hidden' || input.type === 'checkbox') return false;
      if (input.type === 'submit' || input.type === 'button') return false;
      return true;
    });
    const score = (input) => {
      const hint = `${input.name} ${input.id} ${input.autocomplete} ${input.placeholder} ${input.type}`.toLowerCase();
      let result = 0;
      if (/email|e-mail/.test(hint)) result += 6;
      if (/user|login|logname|nick/.test(hint)) result += 5;
      if (/phone|tel|mobile/.test(hint)) result += 4;
      if (/mail/.test(hint)) result += 3;
      if (input.type === 'email') result += 3;
      if (input.autocomplete === 'username' || input.autocomplete === 'email') result += 4;
      if (input.type === 'text') result += 1;
      return result;
    };
    return candidates.sort((a, b) => score(b) - score(a))[0] || null;
  }

  function getFormInfo() {
    const passwordField = findPasswordField();
    if (!passwordField) return { found: false };
    const usernameField = findUsernameField(passwordField);
    const form = passwordField.closest('form');
    return {
      found: true,
      hasForm: Boolean(form),
      action: form?.getAttribute('action') || '',
      method: (form?.getAttribute('method') || '').toUpperCase(),
      usernameName: usernameField?.name || usernameField?.id || '',
      passwordName: passwordField.name || passwordField.id || '',
      url: location.href
    };
  }

  function pickPasswordField(form) {
    const fields = [...form.querySelectorAll('input[type="password"]')].filter(
      (field) => isVisible(field) && field.value
    );
    if (fields.length === 0) return null;
    return (
      fields.find((field) => /new|confirm|again/i.test(`${field.name} ${field.id}`)) ||
      fields[fields.length - 1]
    );
  }

  function readCredentials(passwordField = findPasswordField()) {
    if (!passwordField) return null;
    const usernameField = findUsernameField(passwordField);
    const password = passwordField.value || '';
    if (password.length < 4) return null;
    return {
      origin: location.origin,
      title: document.title || location.hostname,
      username: usernameField?.value || '',
      password
    };
  }

  /* ------------------------------ Shadow UI ---------------------------- */

  const SHADOW_STYLES = `
    :host { all: initial; }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
    .kg-panel {
      position: fixed; right: 20px; bottom: 20px; width: 344px; max-width: calc(100vw - 32px);
      background: linear-gradient(160deg, #171d31 0%, #111625 100%);
      border: 1px solid rgba(139, 92, 246, 0.35);
      border-radius: 16px; padding: 16px; color: #eef2ff;
      box-shadow: 0 24px 60px rgba(2, 6, 23, 0.55), 0 0 0 1px rgba(255,255,255,0.04) inset;
      animation: kg-in 0.28s cubic-bezier(0.22, 1, 0.36, 1);
      z-index: 2147483000;
    }
    .kg-head { display: flex; gap: 10px; align-items: flex-start; }
    .kg-logo {
      width: 34px; height: 34px; border-radius: 10px; flex: 0 0 auto;
      background: linear-gradient(135deg, #8b5cf6, #22d3ee);
      display: grid; place-items: center; color: #0b1020; font-weight: 800; font-size: 15px;
    }
    .kg-title { font-size: 13.5px; font-weight: 700; margin: 0 0 3px; }
    .kg-sub { font-size: 11.5px; color: #9aa6c4; margin: 0; line-height: 1.35; word-break: break-all; }
    .kg-actions { display: flex; gap: 8px; margin-top: 13px; }
    .kg-btn {
      flex: 1; border: 0; border-radius: 10px; padding: 9px 10px; font-size: 12px;
      font-weight: 700; cursor: pointer; transition: transform 0.12s ease, filter 0.12s ease;
    }
    .kg-btn:active { transform: scale(0.97); }
    .kg-btn-primary { background: linear-gradient(135deg, #8b5cf6, #6366f1); color: white; }
    .kg-btn-primary:hover { filter: brightness(1.1); }
    .kg-btn-ghost { background: rgba(255,255,255,0.06); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.08); }
    .kg-close {
      position: absolute; top: 10px; right: 10px; width: 24px; height: 24px; border: 0;
      border-radius: 7px; background: transparent; color: #7c89a8; cursor: pointer; font-size: 15px;
    }
    .kg-close:hover { background: rgba(255,255,255,0.07); color: #e2e8f0; }
    .kg-toast {
      position: fixed; top: 18px; left: 50%; transform: translateX(-50%);
      background: #1b2338; color: #e2e8f0; border: 1px solid rgba(139,92,246,0.4);
      border-radius: 999px; padding: 9px 16px; font-size: 12px; font-weight: 600;
      box-shadow: 0 12px 30px rgba(2,6,23,0.5); z-index: 2147483001;
      animation: kg-in 0.2s ease; max-width: calc(100vw - 40px); text-align: center;
    }
    @keyframes kg-in { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
  `;

  function ensureShadow() {
    if (shadowHost && shadowRoot) return shadowRoot;
    shadowHost = document.getElementById(SHADOW_HOST_ID);
    if (!shadowHost) {
      shadowHost = document.createElement('div');
      shadowHost.id = SHADOW_HOST_ID;
      shadowHost.style.all = 'initial';
      shadowHost.style.position = 'absolute';
      shadowHost.style.width = '0';
      shadowHost.style.height = '0';
      shadowHost.style.overflow = 'visible';
      (document.body || document.documentElement).appendChild(shadowHost);
    }
    shadowRoot = shadowHost.shadowRoot || shadowHost.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = SHADOW_STYLES;
    if (!shadowRoot.querySelector('style')) shadowRoot.appendChild(style);
    return shadowRoot;
  }

  function hidePrompt() {
    if (promptNode) {
      promptNode.remove();
      promptNode = null;
    }
    pendingCredentials = null;
    pendingExistingId = null;
  }

  function showPrompt(mode, data, credentials, existingId) {
    ensureShadow();
    hidePrompt();
    pendingCredentials = credentials;
    pendingExistingId = existingId || null;

    const panel = document.createElement('div');
    panel.className = 'kg-panel';
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-label', 'KeyGuard: сохранить пароль');

    const close = document.createElement('button');
    close.className = 'kg-close';
    close.type = 'button';
    close.setAttribute('aria-label', 'Закрыть');
    close.textContent = '×';

    const head = document.createElement('div');
    head.className = 'kg-head';
    head.innerHTML = `
      <div class="kg-logo">K</div>
      <div>
        <p class="kg-title">${mode === 'update' ? 'Обновить пароль в KeyGuard?' : 'Сохранить пароль в KeyGuard?'}</p>
        <p class="kg-sub">${escapeHtml(data?.title || location.hostname)}${data?.username ? ` · ${escapeHtml(data.username)}` : ''}</p>
      </div>
    `;

    const actions = document.createElement('div');
    actions.className = 'kg-actions';

    const cancel = document.createElement('button');
    cancel.className = 'kg-btn kg-btn-ghost';
    cancel.type = 'button';
    cancel.textContent = 'Отмена';

    const submit = document.createElement('button');
    submit.className = 'kg-btn kg-btn-primary';
    submit.type = 'button';
    submit.textContent = mode === 'update' ? 'Обновить' : 'Сохранить';

    actions.append(cancel, submit);
    panel.append(close, head, actions);

    const finish = async () => {
      const action = mode === 'update' ? 'update' : 'save';
      const payload = {
        type: 'KEYGUARD_PROMPT_ACTION',
        action,
        existingId: pendingExistingId,
        credentials: pendingCredentials
      };
      hidePrompt();
      try {
        await chrome.runtime.sendMessage(payload);
        showToast(action === 'update' ? 'Пароль обновлён в KeyGuard' : 'Пароль сохранён в KeyGuard');
      } catch (error) {
        showToast('Не удалось сохранить: разблокируйте KeyGuard');
      }
    };

    close.addEventListener('click', hidePrompt);
    cancel.addEventListener('click', hidePrompt);
    submit.addEventListener('click', finish);
    panel.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') hidePrompt();
    });

    shadowRoot.appendChild(panel);
    promptNode = panel;
    setTimeout(() => submit.focus(), 30);
  }

  function showToast(text) {
    const root = ensureShadow();
    if (toastNode) toastNode.remove();
    toastNode = document.createElement('div');
    toastNode.className = 'kg-toast';
    toastNode.textContent = text;
    root.appendChild(toastNode);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toastNode?.remove();
      toastNode = null;
    }, 2600);
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[char]));
  }

  /* ------------------------------ Filling ------------------------------ */

  function fillEntry(entry) {
    const passwordField = findPasswordField();
    if (!passwordField) {
      showToast('Поле пароля не найдено на этой странице');
      return { filled: false, reason: 'no-password-field' };
    }
    const usernameField = findUsernameField(passwordField);
    if (entry.username && usernameField) setNativeValue(usernameField, entry.username);
    if (entry.password) setNativeValue(passwordField, entry.password);
    passwordField.focus({ preventScroll: false });
    showToast(entry.title ? `Заполнено: ${entry.title}` : 'Пароль подставлен');
    return { filled: true };
  }

  /* --------------------------- Save detection -------------------------- */

  function maybePrompt(credentials) {
    if (!credentials || !credentials.password) return;
    const key = `${credentials.origin}|${credentials.username}|${credentials.password}`;
    if (lastSent.has(key)) return;
    lastSent.set(key, Date.now());
    if (lastSent.size > 40) {
      const oldest = lastSent.keys().next().value;
      lastSent.delete(oldest);
    }
    chrome.runtime
      .sendMessage({ type: 'KEYGUARD_SUBMITTED', credentials })
      .then((response) => {
        if (!response?.ok || !response.prompt) return;
        showPrompt(response.prompt.mode, response.prompt.entry, credentials, response.prompt.entry?.id);
      })
      .catch(() => {});
  }

  function handleSubmit(event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const passwordField = pickPasswordField(form);
    if (!passwordField) return;
    const credentials = readCredentials(passwordField);
    if (credentials) maybePrompt(credentials);
  }

  function handleChange(event) {
    const target = event.target;
    if (!(target instanceof HTMLInputElement) || target.type !== 'password') return;
    clearTimeout(changeTimer);
    changeTimer = setTimeout(() => {
      const form = target.closest('form');
      const passwordField = form ? pickPasswordField(form) : target;
      const credentials = readCredentials(passwordField || target);
      if (credentials) maybePrompt(credentials);
    }, 1200);
  }

  /* ------------------------------ Messages ----------------------------- */

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    switch (message?.type) {
      case 'KEYGUARD_GET_FORM':
        sendResponse(getFormInfo());
        break;
      case 'KEYGUARD_FILL':
        sendResponse(fillEntry(message.entry || {}));
        break;
      case 'KEYGUARD_TOAST':
        showToast(message.text || '');
        sendResponse({ ok: true });
        break;
      case 'KEYGUARD_CLEAR_CLIPBOARD':
        navigator.clipboard?.writeText('').catch(() => {});
        sendResponse({ ok: true });
        break;
      case 'KEYGUARD_HIDE_PROMPT':
        hidePrompt();
        sendResponse({ ok: true });
        break;
      default:
        break;
    }
    return true;
  });

  document.addEventListener('submit', handleSubmit, true);
  document.addEventListener('change', handleChange, true);

  window.addEventListener('pagehide', () => {
    clearTimeout(changeTimer);
    clearTimeout(toastTimer);
  });
})();
