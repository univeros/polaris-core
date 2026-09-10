import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createClient } from "../src/index.js";

/**
 * The client against the live contract: the Slim demo (examples/slim, installed and set up beforehand)
 * serves Polaris on SQLite and writes its mail to var/mail.log, which is where the verification token
 * comes from. POLARIS_URL points at a running server instead of starting one.
 */
const demo = fileURLToPath(new URL("../../../examples/slim/", import.meta.url));
const baseUrl = process.env["POLARIS_URL"] ?? "http://127.0.0.1:8080";
const email = `ada+${Date.now()}@example.com`;
const password = "Sup3r-Secret-Passw0rd";
let server: ChildProcess | undefined;

async function waitForServer(): Promise<void> {
    for (let attempt = 0; attempt < 100; attempt += 1) {
        try {
            if ((await fetch(`${baseUrl}/auth/.well-known/jwks.json`)).ok) {
                return;
            }
        } catch {
            // not up yet
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`no Polaris at ${baseUrl}; run composer install && bin/setup in examples/slim`);
}

function verificationToken(): string {
    const line = readFileSync(`${demo}var/mail.log`, "utf8")
        .split("\n")
        .filter((entry) => entry.includes(`"${email}"`) && entry.includes('"verify_email"'))
        .at(-1);
    if (line === undefined) {
        throw new Error(`no verification mail for ${email} in ${demo}var/mail.log`);
    }
    const mail: { context: { token: string } } = JSON.parse(line);

    return mail.context.token;
}

beforeAll(async () => {
    if (process.env["POLARIS_URL"] === undefined) {
        server = spawn("php", ["-S", "127.0.0.1:8080", "-t", "public"], { cwd: demo, stdio: "ignore" });
    }
    await waitForServer();
}, 20_000);

afterAll(() => {
    server?.kill();
});

describe("@polaris-auth/client against the Slim demo", () => {
    const anonymous = createClient({ baseUrl });

    it("registers, verifies, logs in and reads /auth/me with the typed client", async () => {
        const registered = await anonymous.POST("/auth/register", { body: { email, password } });
        expect(registered.response.status).toBe(202);
        expect(registered.data?.message).toMatch(/verification/);

        const verified = await anonymous.POST("/auth/email/verify", { body: { token: verificationToken() } });
        expect(verified.response.status).toBe(200);
        expect(verified.data?.message).toBe("Email verified.");

        const login = await anonymous.POST("/auth/login", { body: { email, password } });
        expect(login.response.status).toBe(200);
        expect(login.data).toBeDefined();
        if (login.data === undefined || !("access_token" in login.data.data)) {
            throw new Error("expected a session, not an MFA ticket");
        }
        expect(login.data.data.token_type).toBe("Bearer");
        expect(login.data.data.user.email).toBe(email);

        const me = await anonymous.withToken(login.data.data.access_token).GET("/auth/me");
        expect(me.response.status).toBe(200);
        expect(me.data?.data.email).toBe(email);
        expect(me.data?.data.email_verified).toBe(true);
        expect(anonymous.token).toBeNull();
    });

    it("types the error envelope of an anonymous request", async () => {
        const me = await anonymous.GET("/auth/me");

        expect(me.response.status).toBe(401);
        expect(me.data).toBeUndefined();
        expect(me.error?.error).toBe("unauthorized");
    });

    it("types a validation failure", async () => {
        const login = await anonymous.POST("/auth/login", { body: { email: "not-an-email", password } });

        expect(login.response.status).toBe(422);
        expect(login.error).toBeDefined();
    });
});
