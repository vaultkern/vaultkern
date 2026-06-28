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
        background: "src/background.ts",
        contentScript: "src/contentScript.ts"
      },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "chunks/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]"
      }
    }
  }
});
