import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The hub base URL is read at runtime from VITE_HUB_URL (see src/api/client.ts).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
});
