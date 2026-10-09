import type { PolarisClient } from "./index.js";

/**
 * The browser side of `polaris/passkey`: `navigator.credentials` with the options the routes answer.
 * `registerPasskey()` and `signInWithPasskey()` run a whole ceremony; `passkeyAssertion()` yields the
 * assertion to send as the `code` of core's `POST /auth/mfa/verify` or `/auth/mfa/step-up` when the
 * passkey is the second factor. Needs a secure context (https, or localhost).
 */

/** What the browser needs to make a credential: the JSON the routes answer (WebAuthn Level 3). */
type CreationOptionsJSON = Record<string, unknown>;
type RequestOptionsJSON = Record<string, unknown>;

interface PasskeyRegistration {
    passkey: Record<string, unknown>;
    recovery_codes: string[];
}

export interface SignInWithPasskeyOptions {
    /** Conditional UI: the browser offers the passkey in the form's autofill instead of a prompt (`autocomplete="username webauthn"`). */
    conditional?: boolean;
    signal?: AbortSignal;
}

/**
 * Registers a passkey for the signed-in user of `client` and answers the passkey (and the recovery
 * codes when it is the user's first MFA factor).
 */
export async function registerPasskey(client: PolarisClient, name?: string): Promise<PasskeyRegistration> {
    const options = await client.passkey.registerOptions();
    if (options.data === undefined) {
        throw new Error(describe("POST /passkey/register/options", options.error));
    }
    const credential = await navigator.credentials.create({ publicKey: parseCreationOptions(options.data.data as CreationOptionsJSON) });
    if (!(credential instanceof PublicKeyCredential)) {
        throw new Error("The browser created no passkey.");
    }
    const body: Record<string, unknown> = { credential: serialize(credential) };
    if (name !== undefined) {
        body["name"] = name;
    }
    const registered = await client.passkey.registerVerify({ body } as never);
    if (registered.data === undefined) {
        throw new Error(describe("POST /passkey/register/verify", registered.error));
    }

    return registered.data.data as unknown as PasskeyRegistration;
}

/**
 * Signs in with a passkey (discoverable, or from the form's autofill with `conditional`) and answers
 * core's login envelope, or its `mfa_required` ticket when the authenticator did not verify the user.
 */
export async function signInWithPasskey(client: PolarisClient, options: SignInWithPasskeyOptions = {}): Promise<Record<string, unknown>> {
    const credential = await passkeyAssertion(client, options);
    const verified = await client.passkey.authenticateVerify({ body: { credential: JSON.parse(credential) } } as never);
    if (verified.data === undefined) {
        throw new Error(describe("POST /passkey/authenticate/verify", verified.error));
    }

    return verified.data.data as Record<string, unknown>;
}

/**
 * The assertion for a fresh challenge, as the JSON string the routes take (`credential`, or core's `code`).
 */
export async function passkeyAssertion(client: PolarisClient, options: SignInWithPasskeyOptions = {}): Promise<string> {
    const request = await client.passkey.authenticateOptions();
    if (request.data === undefined) {
        throw new Error(describe("POST /passkey/authenticate/options", request.error));
    }
    const get: CredentialRequestOptions & { mediation?: string } = { publicKey: parseRequestOptions(request.data.data as RequestOptionsJSON) };
    if (options.conditional === true) {
        get.mediation = "conditional";
    }
    if (options.signal !== undefined) {
        get.signal = options.signal;
    }
    const credential = await navigator.credentials.get(get);
    if (!(credential instanceof PublicKeyCredential)) {
        throw new Error("The browser answered no passkey.");
    }

    return JSON.stringify(serialize(credential));
}

/** Whether this browser can autofill a passkey into a form (conditional UI). */
export async function passkeyAutofillAvailable(): Promise<boolean> {
    const api = globalThis.PublicKeyCredential as unknown as { isConditionalMediationAvailable?: () => Promise<boolean> } | undefined;

    return api?.isConditionalMediationAvailable !== undefined ? api.isConditionalMediationAvailable() : false;
}

function parseCreationOptions(json: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
    const api = globalThis.PublicKeyCredential as unknown as { parseCreationOptionsFromJSON?: (json: unknown) => PublicKeyCredentialCreationOptions };
    if (api.parseCreationOptionsFromJSON !== undefined) {
        return api.parseCreationOptionsFromJSON(json);
    }
    const user = json["user"] as Record<string, unknown>;

    return {
        ...json,
        challenge: fromBase64Url(json["challenge"] as string),
        user: { ...user, id: fromBase64Url(user["id"] as string) },
        excludeCredentials: descriptors(json["excludeCredentials"]),
    } as unknown as PublicKeyCredentialCreationOptions;
}

function parseRequestOptions(json: RequestOptionsJSON): PublicKeyCredentialRequestOptions {
    const api = globalThis.PublicKeyCredential as unknown as { parseRequestOptionsFromJSON?: (json: unknown) => PublicKeyCredentialRequestOptions };
    if (api.parseRequestOptionsFromJSON !== undefined) {
        return api.parseRequestOptionsFromJSON(json);
    }

    return { ...json, challenge: fromBase64Url(json["challenge"] as string), allowCredentials: descriptors(json["allowCredentials"]) } as unknown as PublicKeyCredentialRequestOptions;
}

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] {
    return Array.isArray(list) ? list.map((entry: Record<string, unknown>) => ({ ...entry, id: fromBase64Url(entry["id"] as string) }) as PublicKeyCredentialDescriptor) : [];
}

/** `credential.toJSON()` where the browser has it; the same shape by hand otherwise. */
function serialize(credential: PublicKeyCredential): Record<string, unknown> {
    const withJson = credential as PublicKeyCredential & { toJSON?: () => Record<string, unknown> };
    if (withJson.toJSON !== undefined) {
        return withJson.toJSON();
    }
    const response = credential.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
    const body: Record<string, unknown> = { clientDataJSON: toBase64Url(response.clientDataJSON) };
    if (response.attestationObject !== undefined) {
        body["attestationObject"] = toBase64Url(response.attestationObject);
        body["transports"] = typeof response.getTransports === "function" ? response.getTransports() : [];
    } else {
        body["authenticatorData"] = toBase64Url(response.authenticatorData);
        body["signature"] = toBase64Url(response.signature);
        body["userHandle"] = response.userHandle === null ? null : toBase64Url(response.userHandle);
    }

    return {
        id: credential.id,
        rawId: toBase64Url(credential.rawId),
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment ?? null,
        clientExtensionResults: credential.getClientExtensionResults(),
        response: body,
    };
}

function fromBase64Url(encoded: string): ArrayBuffer {
    const binary = atob(encoded.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}

function toBase64Url(buffer: ArrayBuffer): string {
    let binary = "";
    for (const byte of new Uint8Array(buffer)) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function describe(route: string, error: unknown): string {
    const problem = error as { error?: string; detail?: string; message?: string } | undefined;

    return `${route} failed: ${problem?.detail ?? problem?.message ?? problem?.error ?? "unknown error"}`;
}
