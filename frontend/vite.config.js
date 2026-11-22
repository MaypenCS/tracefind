import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// `npm run dev` proxies the API to the Python server on :8000.
// `npm run build` writes the UI into the Python package so `python -m tracefind serve` ships it.
export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': 'http://127.0.0.1:8000' } },
  build: { outDir: '../backend/tracefind/ui', emptyOutDir: true },
})
