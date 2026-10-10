import { decodeBytes, decodeJson, encodeBytes, encodeText } from "./base64url.js";
import { algorithms, type AgentKey, type Jwk } from "./keys.js";

/** A compact JWS signed with the agent's key: `alg`, `kid` and the given headers (`typ`), the claims as the payload. */
export async function sign(key: AgentKey, claims: Record<string, unknown>, headers: Record<string, unknown> = {}): Promise<string> {
    const signingInput = `${encodeText(JSON.stringify({ alg: key.alg, kid: key.kid, ...headers }))}.${encodeText(JSON.stringify(claims))}`;
    const signature = await crypto.subtle.sign(algorithms[key.alg].sign, key.privateKey, new TextEncoder().encode(signingInput));

    return `${signingInput}.${encodeBytes(signature)}`;
}

/** The three decoded parts of a compact JWS, unverified. */
export function decode(jws: string): { header: Record<string, unknown>; claims: Record<string, unknown>; signature: Uint8Array; signingInput: string } {
    const parts = jws.split(".");
    if (parts.length !== 3 || parts.some((part) => part === "")) {
        throw new Error("Not a compact JWS.");
    }
    const [header, payload, signature] = parts as [string, string, string];

    return { header: decodeJson(header), claims: decodeJson(payload), signature: decodeBytes(signature), signingInput: `${header}.${payload}` };
}

/** The WebCrypto import and verify parameters for a server's public JWK, by the JWS `alg`. */
function verifier(alg: unknown): { importParams: RsaHashedImportParams | EcKeyImportParams | Algorithm; verifyParams: AlgorithmIdentifier | RsaPssParams | EcdsaParams } {
    switch (alg) {
        case "RS256":
            return { importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verifyParams: { name: "RSASSA-PKCS1-v1_5" } };
        case "ES256":
            return { importParams: algorithms.ES256.generate, verifyParams: algorithms.ES256.sign };
        case "EdDSA":
            return { importParams: algorithms.EdDSA.generate, verifyParams: algorithms.EdDSA.sign };
        default:
            throw new Error(`Unsupported alg ${String(alg)}.`);
    }
}

/**
 * The claims of a compact JWS whose signature verifies with one of the JWKs (chosen by `kid`, else
 * tried in turn), signed with RS256, ES256 or EdDSA; `typ` must match when given.
 */
export async function verify(jws: string, keys: readonly Jwk[], typ?: string): Promise<{ header: Record<string, unknown>; claims: Record<string, unknown> }> {
    const { header, claims, signature, signingInput } = decode(jws);
    if (typ !== undefined && header["typ"] !== typ) {
        throw new Error(`The JWS is not a ${typ}.`);
    }
    const { importParams, verifyParams } = verifier(header["alg"]);
    const candidates = typeof header["kid"] === "string" ? keys.filter((key) => key.kid === header["kid"]) : keys;
    for (const jwk of candidates) {
        const { kid: _kid, alg: _alg, use: _use, key_ops: _ops, ...bare } = jwk;
        const key = await crypto.subtle.importKey("jwk", bare as JsonWebKey, importParams, false, ["verify"]);
        if (await crypto.subtle.verify(verifyParams, key, signature as BufferSource, new TextEncoder().encode(signingInput))) {
            return { header, claims };
        }
    }
    throw new Error("The signature does not verify with the server's keys.");
}
