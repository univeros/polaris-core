import { encodeBytes, sha256 } from "./base64url.js";
import { canonicalUrl } from "./http.js";
import { sign } from "./jws.js";
import type { AgentKey } from "./keys.js";

/** The request JWT's lifetime: 60 seconds by default, never more than the server's `requestJwtMaxAge` of 300. */
export const DEFAULT_TTL = 60;
export const MAX_TTL = 300;
export const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export interface RequestJwtOptions {
    /** The capabilities this JWT may use; omitted, every live grant of the agent. */
    capabilities?: readonly string[];
    /** Seconds until `exp`; at most 300. */
    ttl?: number;
    /** The clock, for tests. */
    now?: () => number;
}

/** A random `jti`: 128 bits, base64url. */
export function jti(): string {
    return encodeBytes(crypto.getRandomValues(new Uint8Array(16)));
}

/**
 * The signed request JWT of the agent protocol (`typ: agent+jwt`): `sub` = the agent, `aud` = the exact
 * URL called (no query), `iat`, `exp`, a random `jti`, and the request binding Polaris checks when present:
 * `htm`, `htu` and, for a body, `body_hash` (base64url SHA-256 of the exact bytes sent).
 */
export async function requestJwt(key: AgentKey, agentId: string, method: string, url: string, body: string | undefined, options: RequestJwtOptions = {}): Promise<string> {
    const ttl = options.ttl ?? DEFAULT_TTL;
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > MAX_TTL) {
        throw new Error(`ttl must be between 1 and ${MAX_TTL} seconds.`);
    }
    const now = Math.floor((options.now ?? Date.now)() / 1000);
    const aud = canonicalUrl(url);
    const claims: Record<string, unknown> = { sub: agentId, aud, iat: now, exp: now + ttl, jti: jti(), htm: method.toUpperCase(), htu: aud };
    if (body !== undefined) {
        claims["body_hash"] = await sha256(body);
    }
    if (options.capabilities !== undefined) {
        claims["capabilities"] = [...options.capabilities];
    }

    return sign(key, claims, { typ: "agent+jwt" });
}

/** A `private_key_jwt` client assertion (RFC 7523) for the token endpoint: `iss` = `sub` = the agent, `aud` = the endpoint. */
export async function clientAssertion(key: AgentKey, agentId: string, tokenEndpoint: string, now: () => number = Date.now): Promise<string> {
    const issued = Math.floor(now() / 1000);

    return sign(key, { iss: agentId, sub: agentId, aud: tokenEndpoint, jti: jti(), iat: issued, exp: issued + MAX_TTL }, { typ: "JWT" });
}
