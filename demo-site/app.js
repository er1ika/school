/**
 * Демо-сайт «Школьный портал». Нужен только для проверки автозаполнения
 * и сохранения паролей расширением KeyGuard. Данные не отправляются на сервер.
 */
(() => {
  'use strict';

  const banner = document.getElementById('demo-banner');
  let bannerTimer = null;

  function showBanner(text, isError = false) {
    banner.textContent = text;
    banner.classList.toggle('error', isError);
    banner.hidden = false;
    clearTimeout(bannerTimer);
    bannerTimer = setTimeout(() => {
      banner.hidden = true;
    }, 6000);
  }

  document.querySelectorAll('.peek').forEach((button) => {
    button.addEventListener('click', () => {
      const input = document.getElementById(button.dataset.target);
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
      button.textContent = input.type === 'password' ? '👁' : '🙈';
    });
  });

  document.getElementById('login-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    if (!email || !password) {
      showBanner('Заполните логин и пароль.', true);
      return;
    }
    showBanner(`Демо: вход выполнен для ${email}. Пароль не отправлен на сервер.`);
  });

  document.getElementById('password-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const email = document.getElementById('change-email').value.trim();
    const current = document.getElementById('current-password').value;
    const next = document.getElementById('new-password').value;
    if (!email || !current || !next) {
      showBanner('Заполните все поля формы смены пароля.', true);
      return;
    }
    if (next.length < 8) {
      showBanner('Новый пароль должен быть не короче 8 символов.', true);
      return;
    }
    showBanner(`Демо: пароль для ${email} обновлён. KeyGuard может предложить обновить запись.`);
  });
})();
