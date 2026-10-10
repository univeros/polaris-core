import { describe, expect, it } from "vitest";
import { sha256 } from "../src/base64url.js";
import { PolarisAgent, createAgent, discover } from "../src/agent.js";
import { PolarisAgentError } from "../src/http.js";
import { generateAgentKey } from "../src/keys.js";
import { bearer, claimsOf, configuration, grant, mount, recording, verifiesWith } from "./support.js";

const registered = { id: "agent-1", owner_type: "user", owner_id: "u1", organization_id: null, name: "Bot", mode: "delegated", host_id: "h1", auth: "private_key_jwt", public_jwk: null, status: "active", created_by: "u1", sealed_at: null, created_at: "", updated_at: "", grants: [grant()], approval: null };

describe("PolarisAgent", () => {
    it("discovers the configuration under the mount or at the document's own URL", async () => {
        const { requests, fetch } = recording({ body: configuration });
        expect((await discover(`${mount}/`, { fetch })).endpoints.execute).toBe(`${mount}/agents/execute`);
        await discover(`${mount}/.well-known/agent-configuration`, { fetch });
        expect(requests.map((request) => request.url)).toEqual([`${mount}/.well-known/agent-configuration`, `${mount}/.well-known/agent-configuration`]);
        const { fetch: notAgents } = recording({ body: { issuer: "x" } });
        await expect(discover(mount, { fetch: notAgents })).rejects.toThrow("not an agent configuration");
    });

    it("enrols with the host's token and its public JWK, then signs every call with a request JWT for its exact URL and body", async () => {
        const key = await generateAgentKey("ES256");
        const { requests, fetch } = recording({ body: configuration }, { status: 201, body: { data: registered } }, { body: { data: { hello: "world" }, receipt: { id: "r1", seq: 1, hash: "h" } } }, { body: { data: { grants: [grant()] } } });
        const sdk = await createAgent(mount, { fetch, key });
        expect(sdk.agentId).toBeUndefined();
        expect(sdk.mount).toBe(mount);

        const { agent, grants } = await sdk.enroll("peh_token", { name: "Bot", mode: "delegated" });
        expect(agent.agentId).toBe("agent-1");
        expect(grants[0]?.capability).toBe("demo.echo");
        expect(requests[1]).toMatchObject({ method: "POST", url: `${mount}/agents/enroll`, headers: { Authorization: "Bearer peh_token", "Content-Type": "application/json" } });
        expect(JSON.parse(requests[1]!.body!)).toEqual({ name: "Bot", mode: "delegated", auth: "private_key_jwt", jwk: key.publicJwk });

        const executed = await agent.execute<{ hello: string }>("demo.echo", { hello: "world" }, { capabilities: ["demo.echo"] });
        expect(executed.data.hello).toBe("world");
        expect(JSON.parse(requests[2]!.body!)).toEqual({ capability: "demo.echo", arguments: { hello: "world" } });
        const { header, claims } = claimsOf(bearer(requests[2]!));
        expect(header["typ"]).toBe("agent+jwt");
        expect(claims).toMatchObject({ sub: "agent-1", aud: `${mount}/agents/execute`, htm: "POST", htu: `${mount}/agents/execute`, body_hash: await sha256(requests[2]!.body!), capabilities: ["demo.echo"] });
        expect(await verifiesWith(bearer(requests[2]!), key.publicJwk)).toBe(true);

        await agent.session();
        const session = claimsOf(bearer(requests[3]!)).claims;
        expect(session).toMatchObject({ aud: `${mount}/agents/session`, htm: "GET" });
        expect(session).not.toHaveProperty("body_hash");
        expect(() => sdk.execute("demo.echo")).rejects.toThrow("not registered");
    });

    it("registers through the owner's token, with a secret when it has no key, and asks for grants in AAP's shape", async () => {
        const { requests, fetch } = recording({ status: 201, body: { data: { ...registered, auth: "client_secret", client_secret: "pcs_x" } } }, { body: { agent_id: "agent-1", agent_capability_grants: [], approval: null } });
        const sdk = new PolarisAgent({ configuration, fetch });
        const { agent, client_secret } = await sdk.register("owner-token", { name: "Bot", mode: "autonomous", organization_id: "o1", capabilities: ["demo.echo"] });
        expect(client_secret).toBe("pcs_x");
        expect(JSON.parse(requests[0]!.body!)).toEqual({ name: "Bot", mode: "autonomous", auth: "client_secret", organization_id: "o1", capabilities: ["demo.echo"] });

        await agent.withToken("access").requestGrants([{ name: "org.rename", constraints: { name: { pattern: "Acme.*" } } }], { preferred_method: "device_authorization", reason: "Rename" });
        expect(requests[1]).toMatchObject({ method: "POST", url: `${mount}/agents/grants/request`, headers: { Authorization: "Bearer access" } });
        expect(JSON.parse(requests[1]!.body!)).toEqual({ capabilities: [{ name: "org.rename", constraints: { name: { pattern: "Acme.*" } } }], preferred_method: "device_authorization", reason: "Rename" });
        expect(() => agent.execute("demo.echo")).rejects.toThrow("no key and no access token");
    });

    it("mints tokens: client credentials with an assertion, with the secret, and the exchange of a user's token", async () => {
        const key = await generateAgentKey("EdDSA");
        const { requests, fetch } = recording({ body: { access_token: "at", token_type: "Bearer", expires_in: 3600 } });
        const keyed = new PolarisAgent({ configuration, fetch, key, agentId: "agent-1" });
        expect((await keyed.token({ scope: "members.read", resource: `${mount}/mcp` })).access_token).toBe("at");
        const form = new URLSearchParams(requests[0]!.body);
        expect(requests[0]).toMatchObject({ method: "POST", url: `${mount}/oauth2/token`, headers: { "Content-Type": "application/x-www-form-urlencoded" } });
        expect([form.get("grant_type"), form.get("scope"), form.get("resource"), form.get("client_assertion_type")]).toEqual(["client_credentials", "members.read", `${mount}/mcp`, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]);
        const assertion = claimsOf(form.get("client_assertion")!);
        expect(assertion.claims).toMatchObject({ iss: "agent-1", sub: "agent-1", aud: `${mount}/oauth2/token` });
        expect(await verifiesWith(form.get("client_assertion")!, key.publicJwk)).toBe(true);

        const secret = new PolarisAgent({ configuration, fetch, clientSecret: "pcs_x", agentId: "agent-1" });
        await secret.token({ subjectToken: "user-access" });
        const exchange = new URLSearchParams(requests[1]!.body);
        expect(requests[1]!.headers["Authorization"]).toBe(`Basic ${btoa("agent-1:pcs_x")}`);
        expect([exchange.get("grant_type"), exchange.get("subject_token"), exchange.get("subject_token_type"), exchange.has("client_assertion")]).toEqual(["urn:ietf:params:oauth:grant-type:token-exchange", "user-access", "urn:ietf:params:oauth:token-type:access_token", false]);

        await new PolarisAgent({ configuration, fetch, agentId: "agent-1" }).token({ subjectToken: "user-access" });
        expect(new URLSearchParams(requests[2]!.body).get("client_id")).toBe("agent-1");
    });

    it("throws the problem document of a refusal", async () => {
        const problem = { type: "https://polaris.univeros.io/problems/agents/constraint_violated", title: "Forbidden", status: 403, detail: "amount is above 50", error: "constraint_violated", violations: [{ field: "amount", constraint: "max", actual: 60 }] };
        const { fetch } = recording({ status: 403, body: problem });
        const agent = new PolarisAgent({ configuration, fetch, accessToken: "at", agentId: "agent-1" });
        const error = await agent.execute("credits.spend", { amount: 60 }).catch((caught: unknown) => caught);
        expect(error).toBeInstanceOf(PolarisAgentError);
        expect(error).toMatchObject({ status: 403, code: "constraint_violated", problem });
        expect((error as Error).message).toContain("amount is above 50");
    });
});
