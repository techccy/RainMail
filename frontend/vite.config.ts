import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';

// https://vite.dev/config/
export default defineConfig({
  // 构建产物通过 Hono 的 /static/* 服务，base 固定到 /static/spa/
  base: '/static/spa/',
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    // 输出到后端 static 目录下，单端口、单容器部署
    outDir: '../static/spa',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    // 开发期把 API 与会话 cookie 转发到 Hono 后端
    proxy: {
      '/api': 'http://localhost:5024',
      '/auth': 'http://localhost:5024',
      '/user': 'http://localhost:5024',
      '/letters': 'http://localhost:5024',
      '/m': 'http://localhost:5024',
      '/verify-email': 'http://localhost:5024',
      '/static': 'http://localhost:5024',
      '/data': 'http://localhost:5024',
    },
  },
});
