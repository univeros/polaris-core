import { expect, test } from "@playwright/test";

/**
 * The passkey page of the Slim demo (public/passkey.html) with a virtual authenticator (CDP WebAuthn):
 * register, enrol a passkey, sign out, sign in with the passkey alone, pass the MFA gate with it.
 */
test("a passkey registers, signs in and passes the MFA gate on the demo", async ({ page }) => {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
    });

    await page.goto("/passkey.html");
    await page.getByRole("button", { name: "Run the whole flow" }).click();
    await expect(page.locator("#result")).toHaveAttribute("data-state", /pass|fail/, { timeout: 45_000 });
    const log = await page.locator("#log").textContent();
    await expect(page.locator("#result"), log ?? "").toHaveAttribute("data-state", "pass");
    expect(log).toContain('with amr ["passkey"], mfa true');
    expect(log).toContain("passed the MFA gate with the passkey: ok");
});
