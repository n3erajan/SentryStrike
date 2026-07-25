import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // Proxy API calls to the backend so the browser sees same-origin requests
    // (no CORS in dev). The backend mounts everything under /api/v1 on :8000.
    proxy: {
      "/api": {
        target: "http://localhost:8000/",
        changeOrigin: true,
      },
    },
  },
});
