import { encodeBytes, encodeText } from "../src/base64url.js";
import { decode } from "../src/jws.js";
import type { Jwk } from "../src/keys.js";
import type { AgentConfiguration, Approval, Grant, Receipt } from "../src/types.js";

export const mount = "https://auth.polaris.test/api";

export const configuration: AgentConfiguration = {
    version: "1.0-draft",
    provider_name: "Polaris test",
    description: "The unit tests",
    issuer: "https://auth.polaris.test",
    default_location: `${mount}/agents/execute`,
    algorithms: ["ES256", "EdDSA"],
    modes: ["delegated", "autonomous"],
    approval_methods: ["device_authorization", "ciba", "in_app"],
    approval_strengths: { low: "session", medium: "session", high: "step_up" },
    endpoints: {
        register: `${mount}/agents/register`,
        enroll: `${mount}/agents/enroll`,
        capabilities: `${mount}/agents/capabilities`,
        execute: `${mount}/agents/execute`,
        request_capability: `${mount}/agents/grants/request`,
        status: `${mount}/agents/session`,
        revoke: `${mount}/agents`,
        grants: `${mount}/agents/grants`,
        approvals: `${mount}/agents/approvals`,
        receipts: `${mount}/agents/receipts`,
        token: `${mount}/oauth2/token`,
    },
    token_endpoint: `${mount}/oauth2/token`,
};

export function grant(fields: Partial<Grant> = {}): Grant {
    return {
        id: "g1", agent_id: "a1", capability: "demo.echo", constraints: {}, budget: { kind: "count", total: 100, remaining: 100, field: null },
        status: "active", granted_by: null, approved_via: "auto", approval_id: null, expires_at: null, created_at: "2026-10-10T10:00:00+00:00", updated_at: "2026-10-10T10:00:00+00:00",
        ...fields,
    };
}

export function approval(fields: Partial<Approval> = {}): Approval {
    return { id: "ap1", method: "in_app", strength: "session", user_code: null, verification_uri: null, verification_uri_complete: null, expires_in: 60, interval: 5, binding_message: null, ...fields };
}

/** A recording fetch answering each queued response in turn (the last one again when the queue runs out). */
export function recording(...responses: { status?: number; body: unknown }[]) {
    const requests: { method: string; url: string; headers: Record<string, string>; body: string | undefined }[] = [];
    let index = 0;
    const fetch = async (url: string, init: RequestInit): Promise<Response> => {
        const headers: Record<string, string> = {};
        for (const [name, value] of Object.entries(init.headers ?? {})) {
            headers[name] = value;
        }
        requests.push({ method: init.method ?? "GET", url, headers, body: typeof init.body === "string" ? init.body : undefined });
        const next = responses[Math.min(index, responses.length - 1)] ?? { status: 200, body: {} };
        index += 1;
        const status = next.status ?? 200;

        return new Response(JSON.stringify(next.body), { status, headers: { "Content-Type": status >= 400 ? "application/problem+json" : "application/json" } });
    };

    return { requests, fetch };
}

export function bearer(request: { headers: Record<string, string> }): string {
    return request.headers["Authorization"]?.replace(/^Bearer /, "") ?? "";
}

/** The claims of a compact JWS, unverified. */
export function claimsOf(jws: string): { header: Record<string, unknown>; claims: Record<string, unknown> } {
    const { header, claims } = decode(jws);

    return { header, claims };
}

/** True when the JWS verifies with the public JWK, through WebCrypto directly (not the SDK's verifier). */
export async function verifiesWith(jws: string, jwk: Jwk): Promise<boolean> {
    const { signingInput, signature, header } = decode(jws);
    const { kid: _kid, alg: _alg, use: _use, ...bare } = jwk;
    const params = header["alg"] === "EdDSA" ? { name: "Ed25519" } : { name: "ECDSA", namedCurve: "P-256" };
    const key = await crypto.subtle.importKey("jwk", bare as JsonWebKey, params, false, ["verify"]);
    const verify = header["alg"] === "EdDSA" ? { name: "Ed25519" } : { name: "ECDSA", hash: "SHA-256" };

    return crypto.subtle.verify(verify, key, signature as BufferSource, new TextEncoder().encode(signingInput));
}

/** A server key pair of the test: RS256 (core's default) or EdDSA, with its public JWK as the JWKS lists it. */
export async function serverKey(alg: "RS256" | "EdDSA" = "RS256"): Promise<{ privateKey: CryptoKey; jwk: Jwk; alg: string }> {
    const params = alg === "RS256" ? { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" } : { name: "Ed25519" };
    const pair = (await crypto.subtle.generateKey(params, true, ["sign", "verify"])) as CryptoKeyPair;
    const exported = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as Jwk;
    const { key_ops: _ops, ...jwk } = exported;

    return { privateKey: pair.privateKey, jwk: { ...jwk, kid: "server-key", alg, use: "sig" }, alg };
}

/** A receipt+jwt as `Polaris\Agents\Receipts::sign` makes it, over the given hash. */
export async function signReceipt(server: { privateKey: CryptoKey; alg: string }, receipt: Receipt, hash: string): Promise<string> {
    const header = encodeText(JSON.stringify({ typ: "receipt+jwt", alg: server.alg, kid: "server-key" }));
    const payload = encodeText(JSON.stringify({ iss: "https://auth.polaris.test", iat: 1760090400, receipt_hash: hash, receipt_id: receipt.id, agent_id: receipt.agent_id, seq: receipt.seq }));
    const params = server.alg === "RS256" ? { name: "RSASSA-PKCS1-v1_5" } : { name: "Ed25519" };
    const signature = await crypto.subtle.sign(params, server.privateKey, new TextEncoder().encode(`${header}.${payload}`));

    return `${header}.${payload}.${encodeBytes(signature)}`;
}

export function receipt(fields: Partial<Receipt> = {}): Receipt {
    return {
        id: "r1", agent_id: "a1", seq: 1, grant_id: "g1", capability: "demo.echo", input_hash: "ab", outcome: "success", budget_before: 100, budget_after: 99,
        prev_hash: null, hash: "", signature: "", created_at: "2026-10-10T10:00:00+00:00", ...fields,
    };
}
