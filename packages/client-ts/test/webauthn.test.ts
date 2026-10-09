import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createClient, passkeyAssertion, passkeyAutofillAvailable, registerPasskey, signInWithPasskey } from "../src/index.js";

/**
 * The passkey helpers against a fake `navigator.credentials`: the options the routes answer are parsed
 * for the browser (base64url to bytes), the credential the browser makes is sent as the routes take it,
 * and a refused step surfaces the problem document's detail.
 */
const encode = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);
const buffer = (s: string): ArrayBuffer => bytes(s).buffer as ArrayBuffer;

class FakePublicKeyCredential {
    constructor(
        public readonly id: string,
        public readonly rawId: ArrayBuffer,
        public readonly type: string,
        public readonly response: Record<string, unknown>,
        public readonly authenticatorAttachment: string | null = "platform",
    ) {}

    getClientExtensionResults(): Record<string, never> {
        return {};
    }
}

function recording(answers: Array<{ status: number; body: unknown }>) {
    const requests: Array<{ method: string; path: string; body: unknown }> = [];
    const fetch = async (input: Request): Promise<Response> => {
        requests.push({ method: input.method, path: new URL(input.url).pathname, body: input.method === "POST" ? await input.text() : null });
        const next = answers.shift() ?? { status: 500, body: {} };

        return new Response(JSON.stringify(next.body), { status: next.status, headers: { "Content-Type": next.status >= 400 ? "application/problem+json" : "application/json" } });
    };

    return { requests, fetch };
}

describe("the passkey helpers", () => {
    const created: unknown[] = [];
    const got: unknown[] = [];

    beforeEach(() => {
        created.length = 0;
        got.length = 0;
        vi.stubGlobal("PublicKeyCredential", FakePublicKeyCredential);
        vi.stubGlobal("navigator", {
            credentials: {
                create: async (options: { publicKey: Record<string, unknown> }) => {
                    created.push(options);

                    return new FakePublicKeyCredential("cred-1", buffer("cred-1"), "public-key", { clientDataJSON: buffer("{}"), attestationObject: buffer("att"), getTransports: () => ["internal"] });
                },
                get: async (options: { publicKey: Record<string, unknown>; mediation?: string }) => {
                    got.push(options);

                    return new FakePublicKeyCredential("cred-1", buffer("cred-1"), "public-key", { clientDataJSON: buffer("{}"), authenticatorData: buffer("auth"), signature: buffer("sig"), userHandle: buffer("user-1") });
                },
            },
        });
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it("registers a passkey from the options the route answers", async () => {
        const options = { rp: { id: "app.example", name: "App" }, user: { id: encode(bytes("user-1")), name: "ada@example.com", displayName: "Ada" }, challenge: encode(bytes("challenge-1")), pubKeyCredParams: [{ type: "public-key", alg: -7 }], excludeCredentials: [{ type: "public-key", id: encode(bytes("old")) }] };
        const { requests, fetch } = recording([
            { status: 200, body: { data: options } },
            { status: 201, body: { data: { passkey: { id: "p1", name: "MacBook" }, recovery_codes: ["a", "b"] } } },
        ]);
        const client = createClient({ baseUrl: "https://app.example/auth", token: "access", fetch });

        const registered = await registerPasskey(client, "MacBook");

        expect(registered.passkey["name"]).toBe("MacBook");
        expect(registered.recovery_codes).toEqual(["a", "b"]);
        const publicKey = (created[0] as { publicKey: PublicKeyCredentialCreationOptions }).publicKey;
        expect(new TextDecoder().decode(publicKey.challenge as ArrayBuffer)).toBe("challenge-1");
        expect(new TextDecoder().decode(publicKey.user.id as ArrayBuffer)).toBe("user-1");
        expect(new TextDecoder().decode(publicKey.excludeCredentials?.[0]?.id as ArrayBuffer)).toBe("old");
        expect(requests.map((r) => `${r.method} ${r.path}`)).toEqual(["POST /auth/passkey/register/options", "POST /auth/passkey/register/verify"]);
        const sent = JSON.parse(requests[1]?.body as string) as { credential: { id: string; rawId: string; response: Record<string, unknown> }; name: string };
        expect(sent.name).toBe("MacBook");
        expect(sent.credential.id).toBe("cred-1");
        expect(sent.credential.rawId).toBe(encode(bytes("cred-1")));
        expect(sent.credential.response["attestationObject"]).toBe(encode(bytes("att")));
        expect(sent.credential.response["transports"]).toEqual(["internal"]);
    });

    it("signs in with a discoverable passkey, conditionally when asked, and yields an assertion for the MFA code", async () => {
        const request = { challenge: encode(bytes("challenge-2")), rpId: "app.example", allowCredentials: [], userVerification: "preferred" };
        const { requests, fetch } = recording([
            { status: 200, body: { data: request } },
            { status: 200, body: { data: { access_token: "jwt", token_type: "Bearer", user: { email: "ada@example.com" } } } },
            { status: 200, body: { data: request } },
        ]);
        const client = createClient({ baseUrl: "https://app.example", fetch });

        const session = await signInWithPasskey(client, { conditional: true });
        expect(session["access_token"]).toBe("jwt");
        expect((got[0] as { mediation?: string }).mediation).toBe("conditional");
        expect(new TextDecoder().decode((got[0] as { publicKey: PublicKeyCredentialRequestOptions }).publicKey.challenge as ArrayBuffer)).toBe("challenge-2");
        const sent = JSON.parse(requests[1]?.body as string) as { credential: { response: Record<string, unknown> } };
        expect(sent.credential.response["signature"]).toBe(encode(bytes("sig")));
        expect(sent.credential.response["userHandle"]).toBe(encode(bytes("user-1")));

        const code = await passkeyAssertion(client);
        expect(JSON.parse(code)).toMatchObject({ id: "cred-1", type: "public-key" });
        expect((got[1] as { mediation?: string }).mediation).toBeUndefined();
        expect(await passkeyAutofillAvailable()).toBe(false);
    });

    it("surfaces a refused step as the problem's detail", async () => {
        const { fetch } = recording([{ status: 401, body: { error: "unauthorized", message: "Authentication is required." } }]);
        const client = createClient({ baseUrl: "https://app.example", fetch });

        await expect(registerPasskey(client)).rejects.toThrow("POST /passkey/register/options failed: Authentication is required.");
    });
});
