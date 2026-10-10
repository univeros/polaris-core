import { describe, expect, it } from "vitest";
import { sha256 } from "../src/base64url.js";
import { generateAgentKey } from "../src/keys.js";
import { clientAssertion, requestJwt } from "../src/request-jwt.js";
import { claimsOf, verifiesWith } from "./support.js";

describe("the request JWT", () => {
    it("carries the protocol's claims for the exact URL and body, signed with the agent's key", async () => {
        const key = await generateAgentKey("ES256");
        const body = JSON.stringify({ capability: "demo.echo", arguments: { hello: "world" } });
        const jwt = await requestJwt(key, "agent-1", "post", "https://auth.polaris.test/agents/execute?x=1#frag", body, { now: () => 1_760_090_400_000 });
        const { header, claims } = claimsOf(jwt);
        expect(header).toEqual({ alg: "ES256", kid: key.kid, typ: "agent+jwt" });
        expect(claims).toMatchObject({ sub: "agent-1", aud: "https://auth.polaris.test/agents/execute", iat: 1_760_090_400, exp: 1_760_090_460, htm: "POST", htu: "https://auth.polaris.test/agents/execute", body_hash: await sha256(body) });
        expect(claims["jti"]).toMatch(/^[A-Za-z0-9_-]{22}$/);
        expect(claims).not.toHaveProperty("capabilities");
        expect(await verifiesWith(jwt, key.publicJwk)).toBe(true);
    });

    it("signs with EdDSA, restricts the capabilities and omits body_hash without a body", async () => {
        const key = await generateAgentKey("EdDSA");
        const jwt = await requestJwt(key, "agent-1", "GET", "https://auth.polaris.test/agents/session", undefined, { capabilities: ["demo.echo"], ttl: 300 });
        const { header, claims } = claimsOf(jwt);
        expect(header["alg"]).toBe("EdDSA");
        expect(claims["capabilities"]).toEqual(["demo.echo"]);
        expect(claims).not.toHaveProperty("body_hash");
        expect((claims["exp"] as number) - (claims["iat"] as number)).toBe(300);
        expect(await verifiesWith(jwt, key.publicJwk)).toBe(true);
    });

    it("never signs for longer than the server accepts, and two JWTs never share a jti", async () => {
        const key = await generateAgentKey();
        await expect(requestJwt(key, "a", "GET", "https://x.test/", undefined, { ttl: 301 })).rejects.toThrow("300");
        const [first, second] = await Promise.all([requestJwt(key, "a", "GET", "https://x.test/", undefined), requestJwt(key, "a", "GET", "https://x.test/", undefined)]);
        expect(claimsOf(first).claims["jti"]).not.toBe(claimsOf(second).claims["jti"]);
    });

    it("does not verify with another key", async () => {
        const key = await generateAgentKey();
        const other = await generateAgentKey();
        expect(await verifiesWith(await requestJwt(key, "a", "GET", "https://x.test/", undefined), other.publicJwk)).toBe(false);
    });

    it("builds a private_key_jwt assertion for the token endpoint", async () => {
        const key = await generateAgentKey("ES256");
        const assertion = await clientAssertion(key, "agent-1", "https://auth.polaris.test/oauth2/token", () => 1_760_090_400_000);
        const { header, claims } = claimsOf(assertion);
        expect(header).toEqual({ alg: "ES256", kid: key.kid, typ: "JWT" });
        expect(claims).toMatchObject({ iss: "agent-1", sub: "agent-1", aud: "https://auth.polaris.test/oauth2/token", iat: 1_760_090_400, exp: 1_760_090_700 });
        expect(await verifiesWith(assertion, key.publicJwk)).toBe(true);
    });
});
