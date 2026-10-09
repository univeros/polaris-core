import { defineConfig } from "vitest/config";

// The unit and smoke tests only; the Playwright run (e2e/) has its own runner.
export default defineConfig({ test: { include: ["test/**/*.test.ts"] } });
