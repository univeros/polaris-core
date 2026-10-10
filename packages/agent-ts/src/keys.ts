import { sha256 } from "./base64url.js";

/** A JWK as JOSE and Polaris exchange it (the DOM's `JsonWebKey` has no `kid`). */
export interface Jwk {
    kty: string;
    crv?: string;
    x?: string;
    y?: string;
    d?: string;
    n?: string;
    e?: string;
    kid?: string;
    alg?: string;
    use?: string;
    key_ops?: string[];
}

/** The JOSE algorithms an agent signs with: ES256 (an EC P-256 key) or EdDSA (an Ed25519 key). */
export type AgentAlgorithm = "ES256" | "EdDSA";

/** An agent's key pair: the private key stays in WebCrypto, the public JWK goes to Polaris at registration. */
export interface AgentKey {
    readonly alg: AgentAlgorithm;
    readonly kid: string;
    readonly privateKey: CryptoKey;
    /** The public part only, with `kid` and `alg`, as `POST /agents/register` and `/agents/enroll` take it. */
    readonly publicJwk: Jwk;
}

/** The WebCrypto parameters of each algorithm: ES256 is ECDSA over P-256 with SHA-256, EdDSA is Ed25519. */
export const algorithms = {
    ES256: { generate: { name: "ECDSA", namedCurve: "P-256" }, sign: { name: "ECDSA", hash: "SHA-256" } },
    EdDSA: { generate: { name: "Ed25519" }, sign: { name: "Ed25519" } },
} as const;

/**
 * A new key pair. The private key is extractable so `exportPrivateJwk` can persist it for the agent's
 * next run; the SDK itself never sends it anywhere.
 */
export async function generateAgentKey(alg: AgentAlgorithm = "ES256", kid?: string): Promise<AgentKey> {
    const pair = (await crypto.subtle.generateKey(algorithms[alg].generate, true, ["sign", "verify"])) as CryptoKeyPair;

    return fromPair(alg, pair.privateKey, (await crypto.subtle.exportKey("jwk", pair.publicKey)) as Jwk, kid);
}

/** A key pair from a private JWK (`exportPrivateJwk`'s output, or one made elsewhere). */
export async function importAgentKey(privateJwk: Jwk, kid?: string): Promise<AgentKey> {
    const alg = algorithmOf(privateJwk);
    const { kid: _kid, alg: _alg, use: _use, key_ops: _ops, ...bare } = privateJwk;
    const privateKey = await crypto.subtle.importKey("jwk", bare as JsonWebKey, algorithms[alg].generate, true, ["sign"]);
    const { d: _d, ...publicJwk } = bare;

    return fromPair(alg, privateKey, publicJwk, kid ?? privateJwk.kid);
}

/** The private JWK, for the agent's own storage. */
export async function exportPrivateJwk(key: AgentKey): Promise<Jwk> {
    return { ...((await crypto.subtle.exportKey("jwk", key.privateKey)) as Jwk), kid: key.kid, alg: key.alg };
}

/** The JOSE algorithm a JWK signs with, by its type and curve. */
export function algorithmOf(jwk: Jwk): AgentAlgorithm {
    if (jwk.kty === "EC" && jwk.crv === "P-256") {
        return "ES256";
    }
    if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
        return "EdDSA";
    }
    throw new Error("The key must be EC on P-256 (ES256) or OKP on Ed25519 (EdDSA).");
}

/** The RFC 7638 thumbprint of a public JWK (SHA-256 over its required members in lexicographic order). */
export async function thumbprint(jwk: Jwk): Promise<string> {
    const members = jwk.kty === "EC" ? ["crv", "kty", "x", "y"] : jwk.kty === "OKP" ? ["crv", "kty", "x"] : jwk.kty === "RSA" ? ["e", "kty", "n"] : null;
    if (members === null) {
        throw new Error(`No thumbprint for a ${String(jwk.kty)} key.`);
    }
    const canonical: Record<string, string> = {};
    for (const member of members) {
        const value = (jwk as unknown as Record<string, unknown>)[member];
        if (typeof value !== "string") {
            throw new Error(`The key is missing ${member}.`);
        }
        canonical[member] = value;
    }

    return sha256(JSON.stringify(canonical));
}

async function fromPair(alg: AgentAlgorithm, privateKey: CryptoKey, exported: Jwk, kid?: string): Promise<AgentKey> {
    if (exported.crv === undefined || exported.x === undefined) {
        throw new Error("The exported key has no curve or coordinate.");
    }
    const publicJwk: Jwk = { kty: exported.kty, crv: exported.crv, x: exported.x, ...(exported.y === undefined ? {} : { y: exported.y }) };
    const id = kid ?? (await thumbprint(publicJwk));

    return { alg, kid: id, privateKey, publicJwk: { ...publicJwk, alg, kid: id, use: "sig" } };
}
