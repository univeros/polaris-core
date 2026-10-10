import { defineConfig } from "vitest/config";

// The enrol-to-receipt walkthrough against the Slim demo (examples/slim, installed and set up).
export default defineConfig({ test: { include: ["e2e/**/*.e2e.ts"], testTimeout: 60_000, hookTimeout: 30_000 } });
