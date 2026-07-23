import { defineConfig } from "vite";

export default defineConfig({
  test: {
    environment: "jsdom"
  },
  build: {
    minify: "terser",
    terserOptions: {
      compress: { passes: 3 }
    },
    rollupOptions: {
      input: {
        popup: "popup.html",
        background: "src/background.ts",
        contentScript: "src/contentScript.ts",
        autofillShadowPageHook: "src/autofillShadowPageHook.ts",
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
