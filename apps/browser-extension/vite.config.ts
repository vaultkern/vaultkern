import { defineConfig } from "vite";

export default defineConfig({
  test: {
    environment: "jsdom"
  },
  build: {
    rollupOptions: {
      input: {
        popup: "popup.html",
        manager: "manager.html",
        options: "options.html",
        background: "src/background.ts",
        contentScript: "src/contentScript.ts",
        webauthnContentScript: "src/webauthnContentScript.ts",
        webauthnPageHook: "src/webauthnPageHook.ts"
      },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "chunks/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]"
      }
    }
  }
});
