import { defineConfig } from "@playwright/test";
import { resolve } from "node:path";

/**
 * The browser side of the Slim demo (examples/slim): Chromium with a virtual authenticator against the
 * demo served by PHP's built-in server on its own port (the smoke test holds 8080 for a while).
 * `composer install && bin/setup` in examples/slim first; run from packages/client-ts (`npm run e2e`).
 * localhost, not 127.0.0.1: the demo binds its passkeys to the domain.
 */
const demo = resolve(process.cwd(), "../../examples/slim");
const port = 8090;
const baseURL = process.env["POLARIS_URL"] ?? `http://localhost:${port}`;

export default defineConfig({
    testDir: "./e2e",
    timeout: 60_000,
    retries: 0,
    reporter: process.env["CI"] ? "github" : "list",
    use: { baseURL, trace: "retain-on-failure" },
    projects: [{ name: "chromium", use: { browserName: "chromium" } }],
    webServer: process.env["POLARIS_URL"] ? undefined : {
        command: `php -S 127.0.0.1:${port} -t "${resolve(demo, "public")}"`,
        cwd: demo,
        // The demo binds its callbacks and passkeys to this origin (its .env does not override the environment).
        env: { POLARIS_BASE_URL: baseURL },
        // A static file: php -S answers 404 for a routed path whose extension looks static (`.json`).
        url: `http://127.0.0.1:${port}/passkey.html`,
        reuseExistingServer: false,
        timeout: 30_000,
    },
});
