// =============================================================================
// 密码哈希 —— 兼容 Werkzeug 格式（关键兼容点）
// 支持：scrypt:N:r:p$salt$hash、pbkdf2:sha256:N$salt$hash、sha256$salt$hash
// 新哈希采用 Werkzeug 的 scrypt 格式，便于将来回切 Python 也兼容
// 对齐 werkzeug.security.generate_password_hash / check_password_hash
//   关键：Werkzeug 的 salt 是 secrets.token_hex() 生成的 hex **字符串**，
//         直接作为 salt 传给 hashlib.scrypt（即 salt 的字节是该 hex 字符串的 UTF-8）。
//         salt 与 hash 在存储串里都是 hex 字符串。
// =============================================================================
import crypto from 'node:crypto';

const SCRYPT_DEFAULTS = { n: 32768, r: 8, p: 1, keylen: 64 };
const HASH_PREFIXES = ['scrypt:', 'pbkdf2:', 'sha256$'];

/** 恒定时间比较（buffer 形式） */
function timingSafeEqualBuf(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/** 是否是哈希格式 */
export function isHashed(stored: string | null | undefined): boolean {
  if (!stored) return false;
  return HASH_PREFIXES.some((p) => stored.startsWith(p));
}

/** 生成 Werkzeug 风格的 hex salt（token_hex） */
function genSaltHex(byteLen = 16): string {
  return crypto.randomBytes(byteLen).toString('hex');
}

/** 生成新哈希（scrypt 格式，对齐 Werkzeug 默认；salt/hash 均 hex 字符串） */
export function hashPassword(password: string): string {
  const salt = genSaltHex(16); // hex 字符串
  const { n, r, p, keylen } = SCRYPT_DEFAULTS;
  // salt 作为字符串传入（Werkzeug 行为：hashlib.scrypt 接收 str salt，按 utf-8 编码）
  const derived = crypto.scryptSync(password, salt, keylen, { N: n, r, p, maxmem: 256 * n * r * 2 });
  // Werkzeug 格式：scrypt:N:r:p$<hexsalt>$<hexhash>
  return `scrypt:${n}:${r}:${p}$${salt}$${derived.toString('hex')}`;
}

/**
 * 校验密码 —— 兼容 Werkzeug 三种格式
 * 返回是否匹配
 */
export function verifyPassword(password: string, stored: string | null | undefined): boolean {
  if (!stored || typeof stored !== 'string') return false;
  if (!isHashed(stored)) return false;

  try {
    if (stored.startsWith('scrypt:')) {
      // scrypt:N:r:p$<hexsalt>$<hexhash>；salt 作为字符串传入
      const [meta, salt, hashHex] = stored.split('$');
      if (!meta || !salt || !hashHex) return false;
      const params = meta.split(':'); // ['scrypt', 'N', 'r', 'p']
      const N = parseInt(params[1]!, 10);
      const r = parseInt(params[2]!, 10);
      const p = parseInt(params[3]!, 10);
      const expected = Buffer.from(hashHex, 'hex');
      const derived = crypto.scryptSync(password, salt, expected.length, {
        N,
        r,
        p,
        maxmem: 256 * N * r * 2,
      });
      return timingSafeEqualBuf(derived, expected);
    }

    if (stored.startsWith('pbkdf2:')) {
      // pbkdf2:sha256:N$<hexsalt>$<hexhash> （Werkzeug：salt 作为字符串传入，hash 为 hex）
      const firstDollar = stored.indexOf('$');
      const meta = stored.substring(0, firstDollar); // pbkdf2:sha256:N
      const rest = stored.substring(firstDollar + 1); // salt$hash
      const [salt, hashHex] = rest.split('$');
      if (!salt || !hashHex) return false;
      const parts = meta.split(':'); // ['pbkdf2','sha256','N']
      const algorithm = parts[1] || 'sha256';
      const iters = parseInt(parts[2] || '260000', 10);
      const expected = Buffer.from(hashHex, 'hex');
      const derived = crypto.pbkdf2Sync(password, salt, iters, expected.length, algorithm);
      return timingSafeEqualBuf(derived, expected);
    }

    if (stored.startsWith('sha256$')) {
      // sha256$<hexsalt>$<hexhash> （Werkzeug 旧格式，salt 作为字符串）
      const [, salt, hashHex] = stored.split('$');
      if (!salt || !hashHex) return false;
      const expected = Buffer.from(hashHex, 'hex');
      const derived = crypto.createHash('sha256').update(salt + password).digest();
      return timingSafeEqualBuf(derived, expected);
    }
  } catch (e) {
    console.error('[password] 校验失败:', e);
    return false;
  }

  return false;
}
