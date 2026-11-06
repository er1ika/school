/**
 * KeyGuard TOTP — генерация одноразовых кодов (RFC 6238, SHA-1, 6 цифр, 30 секунд).
 * Реализация на Web Crypto, без внешних библиотек.
 */
(() => {
  'use strict';

  const PERIOD = 30;
  const DIGITS = 6;

  function base32Decode(input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
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

  function isBase32(secret) {
    return /^[A-Z2-7\s=]+$/i.test(String(secret || '').trim());
  }

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
    const offset = signature[signature.length - 1] & 0x0f;
    const binary =
      ((signature[offset] & 0x7f) << 24) |
      ((signature[offset + 1] & 0xff) << 16) |
      ((signature[offset + 2] & 0xff) << 8) |
      (signature[offset + 3] & 0xff);
    return String(binary % 10 ** digits).padStart(digits, '0');
  }

  async function generateTotp(secret, timestamp = Date.now()) {
    const counter = Math.floor(timestamp / 1000 / PERIOD);
    const code = await hotp(secret, counter);
    const remaining = PERIOD - (Math.floor(timestamp / 1000) % PERIOD);
    return { code, remaining, period: PERIOD };
  }

  globalThis.KeyGuardTotp = { generateTotp, hotp, base32Decode, isBase32, PERIOD, DIGITS };
})();
