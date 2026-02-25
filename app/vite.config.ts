import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@core":  path.resolve(__dirname, "src/crypto"),
      "@store": path.resolve(__dirname, "src/store"),
      "@ui":    path.resolve(__dirname, "src/components"),
    },
  },
  // Allow WASM imports
  optimizeDeps: {
    exclude: ["ghostpay-core"],
  },
  server: {
    port: 5173,
    host: true,
  },
  build: {
    target:       "es2022",
    rollupOptions: {
      input: "index.html",
    },
  },
});
