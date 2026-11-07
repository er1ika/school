/**
 * KeyGuard TOTP — генерация одноразовых кодов (RFC 6238, SHA-1, 6 цифр, 30 секунд).
 * Реализация на Web Crypto, без внешних библиотек.
 */
(() => {
  'use strict';

  /* =====================================================================
     КАК ЧИТАТЬ ЭТОТ ФАЙЛ
     ---------------------------------------------------------------------
     TOTP — это одноразовый код для двухфакторной аутентификации.
     Секрет (base32) + текущее время → 6 цифр, которые меняются каждые 30 секунд.

     1. base32Decode: переводим секрет в байты.
     2. hotp: считаем HMAC-SHA1 от счётчика.
     3. generateTotp: берём счётчик из времени и возвращаем код.

     Секрет TOTP хранится в зашифрованном хранилище вместе с паролем.
     ===================================================================== */

  /* --- Параметры ---------------------------------------------------- */

  // Период обновления кода и количество цифр.
  const PERIOD = 30;  // секунд на один код
  const DIGITS = 6;  // цифр в коде

  /* --- 1. Base32 ---------------------------------------------------- */

  // Секрет TOTP обычно записан в base32 (A-Z и 2-7).
  // Переводим его в байты, чтобы использовать как ключ HMAC.
  function base32Decode(input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';  // алфавит base32
    const clean = String(input || '').toUpperCase().replace(/=+$/g, '').replace(/\s/g, '');
    let bits = 0;
    let value = 0;
    const output = [];
    for (const char of clean) {
      const index = alphabet.indexOf(char);
      if (index === -1) continue;
      value = (value << 5) | index;
      bits += 5;
      if (bits >= 8) {
        output.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return new Uint8Array(output);
  }

  // Проверяем, что секрет состоит только из символов base32.
  function isBase32(secret) {
    return /^[A-Z2-7\s=]+$/i.test(String(secret || '').trim());
  }

  /* --- 2. HOTP: HMAC от счётчика ------------------------------------ */

  // HOTP — это основа TOTP. Берём секрет и счётчик, считаем HMAC-SHA1,
  // из результата берём 4 байта и переводим в число. Остаток от деления
  // на 10^digits даёт нужное количество цифр.
  async function hotp(secret, counter, digits = DIGITS) {
    const keyBytes = base32Decode(secret);
    if (keyBytes.length === 0) throw new Error('Некорректный TOTP-секрет');
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setUint32(0, Math.floor(counter / 0x100000000));
    view.setUint32(4, counter >>> 0);
    const signature = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, buffer));
    const offset = signature[signature.length - 1] & 0x0f;  // последний байт подсказывает, с какого места взять 4 байта
    const binary =
      ((signature[offset] & 0x7f) << 24) |
      ((signature[offset + 1] & 0xff) << 16) |
      ((signature[offset + 2] & 0xff) << 8) |
      (signature[offset + 3] & 0xff);
    return String(binary % 10 ** digits).padStart(digits, '0');
  }

  /* --- 3. TOTP: время вместо счётчика ------------------------------- */

  // TOTP — это HOTP, где счётчик = текущее время / 30 секунд.
  // Поэтому код одинаковый в течение 30 секунд и потом меняется.
  async function generateTotp(secret, timestamp = Date.now()) {
    const counter = Math.floor(timestamp / 1000 / PERIOD);  // номер 30-секундного интервала
    const code = await hotp(secret, counter);
    const remaining = PERIOD - (Math.floor(timestamp / 1000) % PERIOD);  // сколько секунд осталось до смены кода
    return { code, remaining, period: PERIOD };
  }

  /* --- Что отдаём наружу --------------------------------------------- */

  // popup использует generateTotp, чтобы показать код и таймер.
  globalThis.KeyGuardTotp = { generateTotp, hotp, base32Decode, isBase32, PERIOD, DIGITS };
})();
