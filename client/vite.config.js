import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
    plugins: [react()],
    build: {
        target: 'es2022',
        rollupOptions: {
            output: {
                inlineDynamicImports: true,
                entryFileNames: 'assets/app.js',
                assetFileNames: 'assets/app.[ext]'
            }
        }
    },
    server: {
        port: 5173,
        proxy: {
            '/api': 'http://127.0.0.1:4090',
            '/health': 'http://127.0.0.1:4090',
            '/doctor': 'http://127.0.0.1:4090'
        }
    }
});
