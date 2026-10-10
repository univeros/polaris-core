import { defineConfig } from "vitest/config";

// The unit tests only, against a fake fetch; the walkthrough against the Slim demo is `npm run e2e`.
export default defineConfig({ test: { include: ["test/**/*.test.ts"] } });
