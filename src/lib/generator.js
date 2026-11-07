/**
 * KeyGuard Generator — криптостойкий генератор паролей и оценка надёжности.
 */
(() => {
  'use strict';

  /* =====================================================================
     КАК ЧИТАТЬ ЭТОТ ФАЙЛ
     ---------------------------------------------------------------------
     1. Наборы символов и список популярных паролей.
     2. Безопасная случайность (randomInt, shuffle).
     3. Генерация пароля (generatePassword).
     4. Оценка надёжности (estimateStrength).
     5. Вспомогательные функции для аудита.

     Здесь нет ничего секретного: файл только создаёт пароли и считает
     оценку. Он не сохраняет пароли и не общается с сетью.
     ===================================================================== */
  'use strict';

  /* --- 1. Наборы символов ------------------------------------------- */

  // Каждая группа — это строка, из которой можно выбирать символы.
  // Если группа выключена в настройках, она не попадёт в пул.
  const CHARSETS = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{};:,.?/'
  };

  // Похожие символы, которые легко перепутать: l/I/1, O/0.
  // Режим avoidAmbiguous убирает их из пароля.
  const AMBIGUOUS = /[Il1O0o]/g;

  // Список популярных паролей. Если пароль из списка, он считается
  // слабым, даже если длинный. Список специально небольшой — это пример.
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

  // Последовательности, которые часто используют: abc, 123, qwerty.
  // Они снижают оценку надёжности.
  const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];

  /* --- 2. Безопасная случайность ------------------------------------ */

  // crypto.getRandomValues даёт криптостойкие случайные числа.
  // Rejection sampling нужен, чтобы не было смещения: если остаток
  // диапазона не делится на max, мы отбрасываем «лишние» значения.
  function randomInt(max) {
    if (max <= 0) throw new Error('Некорректный диапазон');
    const limit = Math.floor(0xffffffff / max) * max;  // граница, после которой начинается смещение
    const buffer = new Uint32Array(1);
    let value;
    do {
      crypto.getRandomValues(buffer);
      value = buffer[0];
    } while (value >= limit);  // отбрасываем значения, которые дают смещение
    return value % max;
  }

  // Перемешивание Фишера–Йетса. Нужно, чтобы обязательные символы
  // (по одному из каждой группы) не стояли всегда в начале пароля.
  function shuffle(chars) {
    const array = [...chars];
    for (let i = array.length - 1; i > 0; i -= 1) {
      const j = randomInt(i + 1);
      [array[i], array[j]] = [array[j], array[i]];
    }
    return array.join('');
  }

  // Собираем все разрешённые символы в одну строку.
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
  /* --- 3. Генерация пароля ------------------------------------------ */

  // Алгоритм:
  // 1) проверяем настройки и ограничиваем длину;
  // 2) берём по одному символу из каждой выбранной группы;
  // 3) заполняем оставшиеся позиции символами из общего пула;
  // 4) перемешиваем, чтобы пароль не выглядел предсказуемо.
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
    const length = Math.min(128, Math.max(4, Number(settings.length) || 20));  // длина от 4 до 128
    const groups = [];
    if (settings.lower) groups.push(CHARSETS.lower);
    if (settings.upper) groups.push(CHARSETS.upper);
    if (settings.digits) groups.push(CHARSETS.digits);
    if (settings.symbols) groups.push(CHARSETS.symbols);
    if (groups.length === 0) groups.push(CHARSETS.lower);

    const pool = buildPool(settings) || CHARSETS.lower;

    const required = groups.map((group) => {  // по одному символу из каждой группы
      const filtered = settings.avoidAmbiguous ? group.replace(AMBIGUOUS, '') : group;
      const source = filtered || group;
      return source[randomInt(source.length)];
    });

    const rest = Array.from({ length: Math.max(0, length - required.length) }, () => pool[randomInt(pool.length)]);  // остальные символы из общего пула
    return shuffle([...required, ...rest].slice(0, length).join(''));  // перемешиваем и обрезаем до нужной длины
  }

  // Сколько всего символов доступно. Нужно для оценки энтропии.
  function poolSize(options) {
    let size = 0;
    if (options.lower) size += 26;
    if (options.upper) size += 26;
    if (options.digits) size += 10;
    if (options.symbols) size += CHARSETS.symbols.length;
    if (options.avoidAmbiguous) size -= 5;
    return Math.max(size, 1);
  }

  /* --- 4. Оценка надёжности ----------------------------------------- */

  // Ищем подряд идущие символы алфавита, цифр или клавиатуры.
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

  // Ищем три одинаковых символа подряд: ааа, 111.
  function hasRepeat(password) {
    return /(.)\1{2,}/.test(password);
  }

  /**
   * Оценка надёжности по энтропии (бит) и эвристикам.
   * @returns {{score: number, label: string, entropy: number, checks: object}}
   */
  // Оценка по энтропии (бит) и эвристикам.
  // Энтропия — это «сколько информации» в пароле: длина × log2(алфавит).
  // Штрафы: популярный пароль, последовательности, повторы, короткая длина.
  // Возвращаем score 0..4 и текстовую метку.
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
    let entropy = value.length * Math.log2(pool);  // энтропия = длина × log2(размер алфавита)

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

    if (!checks.noCommon) entropy = Math.min(entropy, 12);  // популярный пароль не может быть надёжным
    if (!checks.noSequence) entropy *= 0.75;
    if (!checks.noRepeat) entropy *= 0.85;
    if (value.length < 8) entropy = Math.min(entropy, 30);  // короткий пароль ограничиваем

    let score = 0;  // пороги оценки: 0..4
    if (entropy >= 28) score = 1;
    if (entropy >= 40) score = 2;
    if (entropy >= 60) score = 3;
    if (entropy >= 80 && checks.length && checks.noCommon) score = 4;
    if (!checks.noCommon) score = Math.min(score, 1);
    if (value.length < 8) score = Math.min(score, 1);

    const labels = ['Очень слабый', 'Слабый', 'Средний', 'Надёжный', 'Отличный'];
    return { score, label: labels[score], entropy: Math.round(entropy), checks };
  }

  /* --- 5. Вспомогательные функции для аудита ------------------------ */

  // Проверка по списку популярных паролей.
  function isCommonPassword(password) {
    return COMMON_PASSWORDS.has(String(password || '').toLowerCase());
  }

  // Сколько дней прошло с даты. Нужно для аудита устаревших паролей.
  function passwordAgeDays(isoDate) {
    if (!isoDate) return 0;
    const created = new Date(isoDate).getTime();
    if (Number.isNaN(created)) return 0;
    return Math.max(0, Math.floor((Date.now() - created) / 86400000));
  }

  /* --- Что отдаём наружу --------------------------------------------- */

  // popup, options и background используют эти функции через
  // globalThis.KeyGuardGenerator.
  globalThis.KeyGuardGenerator = {
    CHARSETS,
    generatePassword,
    estimateStrength,
    isCommonPassword,
    passwordAgeDays,
    poolSize
  };
})();
