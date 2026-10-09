import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";

/**
 * The browser side of the Slim demo (examples/slim): Chromium with a virtual authenticator against the
 * demo served by PHP's built-in server. `composer install && bin/setup` in examples/slim first.
 */
const demo = fileURLToPath(new URL("../../examples/slim/", import.meta.url));
// localhost, not 127.0.0.1: the demo binds its passkeys to the domain.
const baseURL = process.env["POLARIS_URL"] ?? "http://localhost:8080";

export default defineConfig({
    testDir: "./e2e",
    timeout: 60_000,
    retries: 0,
    reporter: process.env["CI"] ? "github" : "list",
    use: { baseURL, trace: "retain-on-failure" },
    projects: [{ name: "chromium", use: { browserName: "chromium" } }],
    webServer: process.env["POLARIS_URL"] ? undefined : {
        command: "php -S 127.0.0.1:8080 -t public",
        cwd: demo,
        url: "http://127.0.0.1:8080/auth/.well-known/jwks.json",
        reuseExistingServer: true,
        timeout: 30_000,
    },
});
