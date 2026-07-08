/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir:      'dist',
    sourcemap:   false,
    // Split vendor chunks for better caching
    rollupOptions: {
      output: {
        manualChunks: {
          react:   ['react', 'react-dom', 'react-router-dom'],
          query:   ['@tanstack/react-query'],
        },
      },
    },
  },
  server: {
    port: 5173,
    // In dev: proxy /api/* to FastAPI so CORS isn't needed during development
    proxy: {
      '/api': {
        target:    'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  test: {
    environment:  'jsdom',
    setupFiles:   ['./src/test/setup.ts'],
    css:          false,
  },
});
