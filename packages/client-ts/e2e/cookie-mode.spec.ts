import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test } from "@playwright/test";

/**
 * Cookie token delivery in a real browser (docs/cookie-mode/spec.md §5): the Slim demo in cookie mode
 * behind the TLS front (e2e/tls-proxy.mjs). The page signs in, refreshes and signs out the way
 * `createClient({ tokenDelivery: "cookie" })` and `refreshSession()` do (same-origin fetch, the CSRF
 * header, an empty refresh body), and the refresh token is never readable by the page.
 */
const origin = process.env["POLARIS_COOKIE_URL"] ?? "https://localhost:8443";
const mailLog = resolve(process.cwd(), "../../examples/slim/var/mail.log");
const password = "Sup3r-Secret-Passw0rd";
// The cookie is scoped to the refresh route; the browser lists it for that URL only.
const refreshUrl = `${origin}/auth/token/refresh`;

test.use({ ignoreHTTPSErrors: true });

function verificationToken(email: string): string {
    const line = readFileSync(mailLog, "utf8").split("\n").filter((entry) => entry.includes(`"${email}"`) && entry.includes('"verify_email"')).at(-1);
    const token = /"token":"([^"]+)"/.exec(line ?? "")?.[1];
    if (token === undefined) {
        throw new Error(`no verification mail for ${email} in ${mailLog}`);
    }

    return token;
}

test("cookie mode signs in, refreshes and signs out without the page ever holding the refresh token", async ({ page, context }) => {
    const email = `cookie+${Date.now()}@example.com`;
    await page.goto(`${origin}/passkey.html`);

    const call = (path: string, body: unknown, token?: string) =>
        page.evaluate(
            async ([path, body, token]) => {
                const headers: Record<string, string> = { "Content-Type": "application/json", "X-Polaris-CSRF": "1" };
                if (token) {
                    headers["Authorization"] = `Bearer ${token}`;
                }
                const response = await fetch(path, { method: "POST", headers, body: JSON.stringify(body) });
                return { status: response.status, body: await response.text() };
            },
            [path, body, token] as const,
        );

    expect((await call("/auth/register", { email, password })).status).toBe(202);
    expect((await call("/auth/email/verify", { token: verificationToken(email) })).status).toBe(200);

    const login = await call("/auth/login", { email, password });
    expect(login.status).toBe(200);
    expect(login.body).not.toContain("refresh_token");
    const access = JSON.parse(login.body).data.access_token as string;

    const cookie = (await context.cookies(refreshUrl)).find((entry) => entry.name === "__Secure-polaris_refresh");
    expect(cookie).toMatchObject({ httpOnly: true, secure: true, sameSite: "Strict", path: "/auth/token/refresh" });
    const readable = await page.evaluate(() => ({ cookie: document.cookie, local: JSON.stringify(localStorage), session: JSON.stringify(sessionStorage) }));
    expect(JSON.stringify(readable)).not.toContain(cookie?.value ?? "<none>");
    expect(readable.cookie).not.toContain("polaris_refresh");

    // Two refreshes in a row: each rotates the cookie the browser sends.
    for (const round of [1, 2]) {
        const refreshed = await call("/auth/token/refresh", {});
        expect(refreshed.status, `refresh ${round}: ${refreshed.body}`).toBe(200);
        expect(refreshed.body).not.toContain("refresh_token");
    }
    const rotated = (await context.cookies(refreshUrl)).find((entry) => entry.name === "__Secure-polaris_refresh");
    expect(rotated?.value).not.toBe(cookie?.value);

    // Without the CSRF header, the same refresh is refused.
    const forged = await page.evaluate(async () => (await fetch("/auth/token/refresh", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).status);
    expect(forged).toBe(403);

    expect((await call("/auth/logout", {}, access)).status).toBe(200);
    expect((await context.cookies(refreshUrl)).find((entry) => entry.name === "__Secure-polaris_refresh")).toBeUndefined();
});
