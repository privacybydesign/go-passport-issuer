import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  return {
    plugins: [
      react(),
    ],
    server: mode === 'development' ? {
      port: 3000,
      host: "0.0.0.0",
      proxy: {
        '/api/start-validation': {
          target: 'http://localhost:8080/',
          changeOrigin: true,
        }
      }
    } : undefined,
    build: {
      outDir: "build",
    },
    test: {
      // Regula's face components register their custom elements and read
      // `location` at import time, so even a pure-logic test that imports their
      // enums needs a DOM.
      environment: 'jsdom',
      setupFiles: ['./src/setupTests.ts'],
    },
  }
});
