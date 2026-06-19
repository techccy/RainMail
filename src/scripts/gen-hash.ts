// 生成 scrypt 密码哈希（Werkzeug 兼容格式），用于 .env 的 ADMIN_PASSWORD
// 用法：npm run gen-hash <password>
import { hashPassword } from '../lib/password.js';

const pwd = process.argv[2];
if (!pwd) {
  console.error('用法: npm run gen-hash <password>');
  process.exit(1);
}
console.log(hashPassword(pwd));
