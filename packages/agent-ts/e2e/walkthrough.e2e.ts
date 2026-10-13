import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, openSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAgent, generateAgentKey, type Receipt } from "../src/index.js";

/**
 * The enrol-to-receipt walkthrough against the Slim demo (examples/slim, installed and set up): an
 * owner registers and logs in, creates a host; the SDK enrols an agent with its own key, requests the
 * demo's low-risk capability (approved by policy), executes it twice, mints a delegated token by
 * exchange, and verifies the receipts and their chain locally against the server's JWKS, as the server
 * does. POLARIS_URL points at a running demo instead of starting one.
 */
const demo = fileURLToPath(new URL("../../../examples/slim/", import.meta.url));
const baseUrl = process.env["POLARIS_URL"] ?? "http://127.0.0.1:8080";
const email = `ada+agent-${Date.now()}@example.com`;
const password = "Sup3r-Secret-Passw0rd";
const serverLog = `${demo}var/server.log`;
let server: ChildProcess | undefined;

async function json<T>(path: string, init: { method?: string; token?: string; body?: unknown } = {}): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json" };
    if (init.token !== undefined) {
        headers["Authorization"] = `Bearer ${init.token}`;
    }
    const response = await fetch(`${baseUrl}${path}`, { method: init.method ?? (init.body === undefined ? "GET" : "POST"), headers, ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }) });
    const text = await response.text();
    if (!response.ok) {
        throw new Error(`${init.method ?? "POST"} ${path} answered ${response.status}: ${text}`);
    }

    return JSON.parse(text) as T;
}

async function waitForServer(): Promise<void> {
    let last = "no response";
    for (let attempt = 0; attempt < 100; attempt += 1) {
        try {
            const response = await fetch(`${baseUrl}/auth/me`);
            if (response.status === 401) {
                return;
            }
            last = `${response.status} ${await response.text()}`;
        } catch (error) {
            last = String(error);
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const log = existsSync(serverLog) ? readFileSync(serverLog, "utf8").split("\n").slice(-10).join("\n") : "";
    throw new Error(`no Polaris at ${baseUrl} (last: ${last}); run composer install && bin/setup in examples/slim\n${log}`);
}

function verificationToken(): string {
    const line = readFileSync(`${demo}var/mail.log`, "utf8").split("\n").filter((entry) => entry.includes(`"${email}"`) && entry.includes('"verify_email"')).at(-1);
    if (line === undefined) {
        throw new Error(`no verification mail for ${email} in ${demo}var/mail.log`);
    }

    return (JSON.parse(line) as { context: { token: string } }).context.token;
}

/** The owner: registered, verified, logged in, in a fresh organization (where they hold members.read). */
async function owner(): Promise<string> {
    await json("/auth/register", { body: { email, password } });
    await json("/auth/email/verify", { body: { token: verificationToken() } });
    const login = await json<{ data: { access_token: string } }>("/auth/login", { body: { email, password } });
    const org = await json<{ data: { id: string } }>("/orgs", { token: login.data.access_token, body: { name: `Acme ${Date.now()}` } });
    const switched = await json<{ data: { access_token: string } }>("/auth/switch-org", { token: login.data.access_token, body: { organization_id: org.data.id } });

    return switched.data.access_token;
}

beforeAll(async () => {
    if (process.env["POLARIS_URL"] === undefined) {
        const log = openSync(serverLog, "w");
        server = spawn("php", ["-S", "127.0.0.1:8080", "-t", "public", "public/index.php"], { cwd: demo, stdio: ["ignore", log, log] });
    }
    await waitForServer();
}, 20_000);

afterAll(() => {
    server?.kill();
});

describe("@polaris-auth/agent against the Slim demo", () => {
    it("enrols through a host, gets the low-risk capability by policy, executes it and verifies the receipt chain", async () => {
        const ownerToken = await owner();
        const host = await json<{ data: { id: string; enrollment_token: string } }>("/agents/hosts", { token: ownerToken, body: { name: "Laptop" } });

        // The SDK: discovery, an Ed25519 key of its own, enrolment with the host's token.
        const key = await generateAgentKey("EdDSA");
        const sdk = await createAgent(baseUrl, { key });
        expect(sdk.configuration.provider_name).toBe("Polaris demo");
        expect(sdk.configuration.endpoints.mcp).toMatch(/\/mcp$/);
        const { agent, host_id, public_jwk } = await sdk.enroll(host.data.enrollment_token, { name: "Claude Code", mode: "delegated" });
        expect(host_id).toBe(host.data.id);
        expect(public_jwk).toMatchObject({ kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid: key.kid });

        // The grant: low risk, the owner holds members.read, so the policy approves it with a budget of 100.
        const asked = await agent.requestGrants(["demo.echo"], { reason: "The walkthrough" });
        expect(asked.agent_id).toBe(agent.agentId);
        expect(asked.agent_capability_grants.map((grant) => [grant.capability, grant.status, grant.approved_via])).toEqual([["demo.echo", "active", "auto"]]);
        expect(asked.approval ?? null).toBeNull();
        const capabilities = await agent.capabilities();
        expect(capabilities.find((capability) => capability.name === "demo.echo")?.grant_status).toBe("active");

        // Two executions with signed request JWTs: the handler echoes, the receipts chain.
        const first = await agent.execute<{ echo: { message: string } }>("demo.echo", { message: "hello" });
        expect(first.data.echo.message).toBe("hello");
        expect(first.receipt.seq).toBe(1);
        const second = await agent.execute("demo.echo", { message: "again" });
        expect(second.receipt.seq).toBe(2);
        const session = await agent.session();
        expect([session.authenticated_via, session.host?.name, session.grants[0]?.budget?.remaining]).toEqual(["jwt", "Laptop", 98]);

        // A delegated token by exchange, authenticated with a private_key_jwt assertion; it works on the agent's routes.
        const token = await agent.token({ subjectToken: ownerToken, scope: "members.read" });
        expect(token.token_type).toBe("Bearer");
        expect((await agent.withToken(token.access_token).session()).authenticated_via).toBe("oauth");

        // The chain, as the owner lists it, verified locally against the JWKS and remotely by the server.
        const chain = await json<{ data: Receipt[] }>(`/agents/${agent.agentId}/receipts`, { token: ownerToken });
        expect(chain.data.map((receipt) => receipt.seq)).toEqual([1, 2]);
        const [one, two] = chain.data as [Receipt, Receipt];
        expect(await agent.verifyReceipt(one)).toEqual({ valid: true, checks: { hash: true, signature: true, chain: true } });
        expect(await agent.verifyReceipt(two, one)).toEqual({ valid: true, checks: { hash: true, signature: true, chain: true } });
        expect((await agent.verifyReceipt({ ...two, prev_hash: (one.hash[0] === "0" ? "1" : "0") + one.hash.slice(1) }, one)).checks).toMatchObject({ hash: false, signature: false, chain: false });
        const remote = await json<{ data: { valid: boolean } }>(`/agents/receipts/${two.id}/verify`, { token: ownerToken });
        expect(remote.data.valid).toBe(true);
    });
});
