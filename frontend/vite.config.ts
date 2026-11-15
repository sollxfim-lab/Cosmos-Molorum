import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (id.includes("@xterm")) return "xterm";
          if (id.includes("react")) return "react";
          return "vendor";
        },
      },
    },
  },
  server: {
    host: "0.0.0.0",
    port: 5173,
    allowedHosts: [".monkeycode-ai.live", ".onrender.com"],
    proxy: {
      "/api": { target: "https://cosmos-molorum-1.onrender.com:45265", changeOrigin: true },
      "/ws": { target: "ws://cosmos-molorum-1.onrender.com:45265", ws: true },
      "/gate": { target: "https://cosmos-molorum-1.onrender.com:45265", changeOrigin: true },
    },
  },
  preview: {
    host: "0.0.0.0",
    port: 5173,
    allowedHosts: [".onrender.com"],
  },
});
