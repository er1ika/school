/**
 * KeyGuard Generator — криптостойкий генератор паролей и оценка надёжности.
 */
(() => {
  'use strict';

  const CHARSETS = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{};:,.?/'
  };

  const AMBIGUOUS = /[Il1O0o]/g;

  const COMMON_PASSWORDS = new Set([
    'password', 'password1', 'password123', '12345678', '123456789', '1234567890',
    'qwerty', 'qwerty123', 'qwertyuiop', '111111', '000000', '123123', '654321',
    'admin', 'admin123', 'root', 'toor', 'letmein', 'welcome', 'welcome1',
    'iloveyou', 'monkey', 'dragon', 'sunshine', 'princess', 'football', 'baseball',
    'master', 'shadow', 'superman', 'michael', 'jennifer', 'trustno1', 'passw0rd',
    'p@ssw0rd', 'p@ssword', 'qwertyui', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
    '1q2w3e4r', '1q2w3e4r5t', 'qazwsx', 'qwe123', 'abc123', 'test123', 'test',
    'changeme', 'secret', 'default', 'access', 'login', 'hello', 'hello123',
    'school', 'school123', 'student', 'student123', 'moscow', 'russia', 'кпароль'
  ]);

  const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];

  function randomInt(max) {
    if (max <= 0) throw new Error('Некорректный диапазон');
    const limit = Math.floor(0xffffffff / max) * max;
    const buffer = new Uint32Array(1);
    let value;
    do {
      crypto.getRandomValues(buffer);
      value = buffer[0];
    } while (value >= limit);
    return value % max;
  }

  function shuffle(chars) {
    const array = [...chars];
    for (let i = array.length - 1; i > 0; i -= 1) {
      const j = randomInt(i + 1);
      [array[i], array[j]] = [array[j], array[i]];
    }
    return array.join('');
  }

  function buildPool(options) {
    let pool = '';
    if (options.lower) pool += CHARSETS.lower;
    if (options.upper) pool += CHARSETS.upper;
    if (options.digits) pool += CHARSETS.digits;
    if (options.symbols) pool += CHARSETS.symbols;
    if (options.avoidAmbiguous) pool = pool.replace(AMBIGUOUS, '');
    return pool;
  }

  /**
   * Генерирует пароль, гарантируя наличие хотя бы одного символа из каждой
   * выбранной группы (если длина позволяет).
   */
  function generatePassword(options = {}) {
    const settings = {
      length: 20,
      lower: true,
      upper: true,
      digits: true,
      symbols: true,
      avoidAmbiguous: true,
      ...options
    };
    const length = Math.min(128, Math.max(4, Number(settings.length) || 20));
    const groups = [];
    if (settings.lower) groups.push(CHARSETS.lower);
    if (settings.upper) groups.push(CHARSETS.upper);
    if (settings.digits) groups.push(CHARSETS.digits);
    if (settings.symbols) groups.push(CHARSETS.symbols);
    if (groups.length === 0) groups.push(CHARSETS.lower);

    const pool = buildPool(settings) || CHARSETS.lower;

    const required = groups.map((group) => {
      const filtered = settings.avoidAmbiguous ? group.replace(AMBIGUOUS, '') : group;
      const source = filtered || group;
      return source[randomInt(source.length)];
    });

    const rest = Array.from({ length: Math.max(0, length - required.length) }, () => pool[randomInt(pool.length)]);
    return shuffle([...required, ...rest].slice(0, length).join(''));
  }

  function poolSize(options) {
    let size = 0;
    if (options.lower) size += 26;
    if (options.upper) size += 26;
    if (options.digits) size += 10;
    if (options.symbols) size += CHARSETS.symbols.length;
    if (options.avoidAmbiguous) size -= 5;
    return Math.max(size, 1);
  }

  function hasSequence(password) {
    const lower = password.toLowerCase();
    return SEQUENCES.some((sequence) => {
      for (let i = 0; i + 3 <= sequence.length; i += 1) {
        const chunk = sequence.slice(i, i + 4);
        if (lower.includes(chunk)) return true;
      }
      return false;
    });
  }

  function hasRepeat(password) {
    return /(.)\1{2,}/.test(password);
  }

  /**
   * Оценка надёжности по энтропии (бит) и эвристикам.
   * @returns {{score: number, label: string, entropy: number, checks: object}}
   */
  function estimateStrength(password) {
    const value = typeof password === 'string' ? password : '';
    if (!value) {
      return { score: 0, label: 'Нет пароля', entropy: 0, checks: {} };
    }
    let pool = 0;
    if (/[a-zа-я]/.test(value)) pool += 26;
    if (/[A-ZА-Я]/.test(value)) pool += 26;
    if (/[0-9]/.test(value)) pool += 10;
    if (/[^a-zA-Zа-яА-Я0-9]/.test(value)) pool += 32;
    pool = Math.max(pool, 1);
    let entropy = value.length * Math.log2(pool);

    const checks = {
      length: value.length >= 12,
      long: value.length >= 16,
      upper: /[A-ZА-Я]/.test(value),
      lower: /[a-zа-я]/.test(value),
      digit: /[0-9]/.test(value),
      symbol: /[^a-zA-Zа-яА-Я0-9]/.test(value),
      noCommon: !COMMON_PASSWORDS.has(value.toLowerCase()),
      noSequence: !hasSequence(value),
      noRepeat: !hasRepeat(value)
    };

    if (!checks.noCommon) entropy = Math.min(entropy, 12);
    if (!checks.noSequence) entropy *= 0.75;
    if (!checks.noRepeat) entropy *= 0.85;
    if (value.length < 8) entropy = Math.min(entropy, 30);

    let score = 0;
    if (entropy >= 28) score = 1;
    if (entropy >= 40) score = 2;
    if (entropy >= 60) score = 3;
    if (entropy >= 80 && checks.length && checks.noCommon) score = 4;
    if (!checks.noCommon) score = Math.min(score, 1);
    if (value.length < 8) score = Math.min(score, 1);

    const labels = ['Очень слабый', 'Слабый', 'Средний', 'Надёжный', 'Отличный'];
    return { score, label: labels[score], entropy: Math.round(entropy), checks };
  }

  function isCommonPassword(password) {
    return COMMON_PASSWORDS.has(String(password || '').toLowerCase());
  }

  function passwordAgeDays(isoDate) {
    if (!isoDate) return 0;
    const created = new Date(isoDate).getTime();
    if (Number.isNaN(created)) return 0;
    return Math.max(0, Math.floor((Date.now() - created) / 86400000));
  }

  globalThis.KeyGuardGenerator = {
    CHARSETS,
    generatePassword,
    estimateStrength,
    isCommonPassword,
    passwordAgeDays,
    poolSize
  };
})();
