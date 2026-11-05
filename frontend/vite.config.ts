import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// En développement, l'API est jointe à travers Caddy (pile Docker démarrée).
export default defineConfig({
  plugins: [react()],
  build: {
    modulePreload: { polyfill: false }, // aucun script en ligne : compatible avec la CSP stricte
    assetsInlineLimit: 0, // aucune police en ligne : la CSP n'autorise que font-src 'self'
    sourcemap: false,
  },
  server: {
    proxy: {
      "/api": { target: "https://localhost", changeOrigin: true, secure: false },
    },
  },
});
