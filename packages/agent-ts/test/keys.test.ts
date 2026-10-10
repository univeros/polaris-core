import { describe, expect, it } from "vitest";
import { exportPrivateJwk, generateAgentKey, importAgentKey, thumbprint } from "../src/keys.js";

describe("agent keys", () => {
    it("generates an ES256 key whose kid is its RFC 7638 thumbprint and whose public JWK has no private part", async () => {
        const key = await generateAgentKey();
        expect(key.alg).toBe("ES256");
        expect(key.publicJwk).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256", use: "sig", kid: key.kid });
        expect(key.publicJwk).not.toHaveProperty("d");
        expect(key.kid).toBe(await thumbprint({ kty: "EC", crv: "P-256", x: key.publicJwk.x!, y: key.publicJwk.y! }));
    });

    it("generates an Ed25519 key for EdDSA, with a given kid", async () => {
        const key = await generateAgentKey("EdDSA", "my-agent-key");
        expect(key.publicJwk).toMatchObject({ kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid: "my-agent-key" });
        expect(key.publicJwk).not.toHaveProperty("y");
    });

    it("exports the private JWK for storage and imports it back to the same public key", async () => {
        const key = await generateAgentKey("ES256");
        const stored = await exportPrivateJwk(key);
        expect(stored.d).toBeTypeOf("string");
        const again = await importAgentKey(stored);
        expect(again.publicJwk).toEqual(key.publicJwk);
        expect(again.kid).toBe(key.kid);
    });

    it("refuses a key that is neither P-256 nor Ed25519", async () => {
        await expect(importAgentKey({ kty: "EC", crv: "P-384", x: "x", y: "y", d: "d" })).rejects.toThrow("ES256");
    });

    it("computes the thumbprint over the canonical members in order", async () => {
        // RFC 7638 §3.1's RSA example.
        const n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        expect(await thumbprint({ kty: "RSA", e: "AQAB", n })).toBe("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    });
});
