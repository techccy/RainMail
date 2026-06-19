import { defineConfig } from 'drizzle-kit';

// 与 src/db/index.ts 使用同一份 DATABASE_PATH 逻辑
const dbFile = process.env.DATABASE_PATH?.replace(/^sqlite:\/\//, '') || 'instance/rainmail.db';

export default defineConfig({
  schema: './src/db/schema.ts',
  out: './drizzle',
  dialect: 'sqlite',
  dbCredentials: {
    url: dbFile,
  },
});
