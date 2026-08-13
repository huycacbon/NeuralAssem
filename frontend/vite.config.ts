import { fileURLToPath, URL } from 'node:url';

import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The dev server binds to loopback only: this tool analyses untrusted samples
// and is never meant to be reachable from the network.
export default defineConfig({
  plugins: [react()],
  // Relative asset URLs (`./assets/x.js` instead of `/assets/x.js`) so the
  // build works unchanged whether it is served from the web root (uvicorn)
  // or from pywebview's local static server in the desktop build - both
  // just need paths relative to wherever index.html itself was served from.
  base: './',
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: false,
    // Dev-mode only: forwards /api/* to the backend so the frontend can use
    // plain relative paths everywhere. In the packaged desktop build the
    // backend serves this app's own static files, so /api/* is already
    // same-origin there and needs no proxy at all - one URL scheme, two ways
    // of satisfying it.
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  preview: {
    host: '127.0.0.1',
    port: 4173,
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
  },
});
