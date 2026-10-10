import { waitForApproval, type WaitOptions } from "./approvals.js";
import { call, canonicalUrl, routeUrl, type Fetch } from "./http.js";
import type { AgentKey, Jwk } from "./keys.js";
import { verifyReceipt } from "./receipts.js";
import { ASSERTION_TYPE, clientAssertion, requestJwt } from "./request-jwt.js";
import { routes } from "./routes.js";
import type { AgentConfiguration, Approval, Capability, ExecuteResult, Grant, GrantRequestResult, Receipt, ReceiptVerification, Registered, Session, TokenResponse } from "./types.js";

export const DISCOVERY_PATH = routes.configuration.path;
export const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
export const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

export interface AgentOptions {
    /** The discovery document (`discover()`), which names every endpoint. */
    configuration: AgentConfiguration;
    /** The agent's key: request JWTs and `private_key_jwt` assertions are signed with it. */
    key?: AgentKey;
    /** The agent's id, once registered or enrolled (a `register`/`enroll` result binds it for you). */
    agentId?: string;
    /** An OAuth access token to send instead of a request JWT (`token()` mints one). */
    accessToken?: string;
    /** The `pcs_` secret of a `client_secret` agent, for `token()`. */
    clientSecret?: string;
    fetch?: Fetch;
    /** Seconds a request JWT lives; 60 by default, at most 300. */
    jwtTtl?: number;
    now?: () => number;
}

export interface RegisterInput {
    name: string;
    mode: "delegated" | "autonomous";
    /** `private_key_jwt` when the agent has a key (its public JWK is sent), else `client_secret`. */
    auth?: "private_key_jwt" | "client_secret" | "delegated_token";
    organization_id?: string;
    capabilities?: readonly CapabilityRequest[];
}

export type CapabilityRequest = string | { name: string; constraints?: Record<string, unknown> };

export interface GrantRequestOptions {
    reason?: string;
    preferred_method?: "device_authorization" | "ciba" | "in_app";
    binding_message?: string;
}

export interface TokenOptions {
    scope?: string;
    /** The resource the token is for (`<mount>/mcp` for the MCP server); the issuer when omitted. */
    resource?: string;
    audience?: string;
    /** A user's access token: RFC 8693 token exchange for a delegated agent; client credentials without it. */
    subjectToken?: string;
}

/** The discovery document at `<mount>/.well-known/agent-configuration` (the mount, or the document's own URL). */
export async function discover(url: string, options: { fetch?: Fetch } = {}): Promise<AgentConfiguration> {
    const trimmed = url.replace(/\/+$/, "");
    const documentUrl = trimmed.endsWith(DISCOVERY_PATH) ? trimmed : `${trimmed}${DISCOVERY_PATH}`;
    const configuration = await call<AgentConfiguration>(options.fetch ?? fetch, documentUrl, { method: "GET" });
    if (typeof configuration.endpoints?.execute !== "string" || typeof configuration.token_endpoint !== "string") {
        throw new Error(`${documentUrl} is not an agent configuration document.`);
    }

    return configuration;
}

/** `discover()` then `new PolarisAgent()`, in one call. */
export async function createAgent(url: string, options: Omit<AgentOptions, "configuration"> = {}): Promise<PolarisAgent> {
    return new PolarisAgent({ ...options, configuration: await discover(url, options.fetch === undefined ? {} : { fetch: options.fetch }) });
}

/**
 * An agent of a Polaris server: registers or enrols, asks for grants and waits for their approval,
 * executes capabilities with a signed request JWT (or an access token), mints tokens and verifies
 * receipts. Immutable: `register`, `enroll` and `withToken` answer a new instance bound to the result.
 */
export class PolarisAgent {
    readonly configuration: AgentConfiguration;
    readonly agentId: string | undefined;
    private readonly options: AgentOptions;
    private readonly fetchImpl: Fetch;
    private jwks: Promise<readonly Jwk[]> | undefined;

    constructor(options: AgentOptions) {
        this.options = options;
        this.configuration = options.configuration;
        this.agentId = options.agentId;
        this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
    }

    /** Where Polaris is mounted, read off the discovery document's execute endpoint. */
    get mount(): string {
        const execute = this.configuration.endpoints.execute;

        return execute.endsWith(routes.execute.path) ? execute.slice(0, -routes.execute.path.length) : execute.replace(/\/agents\/execute$/, "");
    }

    /** The same agent sending an access token (from `token()`) instead of request JWTs. */
    withToken(accessToken: string): PolarisAgent {
        return new PolarisAgent({ ...this.options, accessToken, ...(this.agentId === undefined ? {} : { agentId: this.agentId }) });
    }

    /** The agent registered by its owner (`ownerToken`: the owner's access token); the result carries the bound agent. */
    async register(ownerToken: string, input: RegisterInput): Promise<Registered & { agent: PolarisAgent }> {
        const registered = await this.post<{ data: Registered }>(routes.register.path, this.registration(input), `Bearer ${ownerToken}`);

        return { ...registered.data, agent: new PolarisAgent({ ...this.options, agentId: registered.data.id }) };
    }

    /** The agent enrolled through a host (`enrollmentToken`: the host's `peh_...` token); the result carries the bound agent. */
    async enroll(enrollmentToken: string, input: Omit<RegisterInput, "organization_id" | "capabilities">): Promise<Registered & { agent: PolarisAgent }> {
        const enrolled = await this.post<{ data: Registered }>(routes.enroll.path, this.registration(input), `Bearer ${enrollmentToken}`);

        return { ...enrolled.data, agent: new PolarisAgent({ ...this.options, agentId: enrolled.data.id }) };
    }

    /** `POST /agents/grants/request`: what the policy approves is active at once, the rest waits in `approval`. */
    async requestGrants(capabilities: readonly CapabilityRequest[], options: GrantRequestOptions = {}): Promise<GrantRequestResult> {
        return this.post<GrantRequestResult>(routes.requestGrants.path, { capabilities: [...capabilities], ...options });
    }

    /** Polls the agent's session until the approval's grants are active; throws `ApprovalError` on denial, expiry or abort. */
    async waitForApproval(approval: Approval, options: WaitOptions = {}): Promise<Grant[]> {
        return waitForApproval(approval, async () => (await this.session()).grants, options);
    }

    /** `POST /agents/execute`: the handler's result and the receipt appended to the agent's chain. */
    async execute<T = unknown>(capability: string, args: Record<string, unknown> = {}, options: { capabilities?: readonly string[] } = {}): Promise<ExecuteResult<T>> {
        return this.post<ExecuteResult<T>>(routes.execute.path, { capability, arguments: args }, undefined, options.capabilities);
    }

    /** `GET /agents/session`: the agent, its owner, its host and its grants with their remaining budgets. */
    async session(): Promise<Session> {
        return (await this.get<{ data: Session }>(routes.session.path)).data;
    }

    /** `GET /agents/capabilities`, with `grant_status` when the agent authenticates. */
    async capabilities(): Promise<Capability[]> {
        const credential = this.agentId !== undefined && (this.options.key !== undefined || this.options.accessToken !== undefined) ? await this.credential("GET", routeUrl(this.mount, routes.capabilities.path)) : undefined;
        const headers = credential === undefined ? {} : { Authorization: credential };

        return (await call<{ data: { capabilities: Capability[] } }>(this.fetchImpl, routeUrl(this.mount, routes.capabilities.path), { method: "GET", headers })).data.capabilities;
    }

    /**
     * A token from the OAuth token endpoint: client credentials for an autonomous agent, or the exchange
     * of a user's access token (`subjectToken`) for a delegated one. The client authenticates with a
     * `private_key_jwt` assertion signed by the key, or with the `client_secret` (HTTP Basic).
     */
    async token(options: TokenOptions = {}): Promise<TokenResponse> {
        const agentId = this.requireAgentId();
        const endpoint = this.configuration.token_endpoint;
        const form = new URLSearchParams();
        const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
        if (this.options.key !== undefined) {
            form.set("client_assertion_type", ASSERTION_TYPE);
            form.set("client_assertion", await clientAssertion(this.options.key, agentId, endpoint, this.options.now));
        } else if (this.options.clientSecret !== undefined) {
            headers["Authorization"] = `Basic ${btoa(`${agentId}:${this.options.clientSecret}`)}`;
        } else {
            form.set("client_id", agentId);
        }
        if (options.subjectToken !== undefined) {
            form.set("grant_type", TOKEN_EXCHANGE);
            form.set("subject_token", options.subjectToken);
            form.set("subject_token_type", ACCESS_TOKEN_TYPE);
        } else {
            form.set("grant_type", "client_credentials");
        }
        for (const [name, value] of Object.entries({ scope: options.scope, resource: options.resource, audience: options.audience })) {
            if (value !== undefined) {
                form.set(name, value);
            }
        }

        return call<TokenResponse>(this.fetchImpl, endpoint, { method: "POST", body: form.toString(), headers });
    }

    /** Verifies a receipt locally against the server's JWKS (fetched once per agent), and its link to `previous` when given. */
    async verifyReceipt(receipt: Receipt, previous?: Receipt | null): Promise<ReceiptVerification> {
        this.jwks ??= call<{ keys: Jwk[] }>(this.fetchImpl, routeUrl(this.mount, routes.jwks.path), { method: "GET" }).then((set) => set.keys);

        return verifyReceipt(receipt, await this.jwks, previous);
    }

    private registration(input: RegisterInput): Record<string, unknown> {
        const auth = input.auth ?? (this.options.key === undefined ? "client_secret" : "private_key_jwt");
        if (auth === "private_key_jwt" && this.options.key === undefined) {
            throw new Error("private_key_jwt needs a key (generateAgentKey or importAgentKey).");
        }

        return { ...input, auth, ...(auth === "private_key_jwt" ? { jwk: this.options.key?.publicJwk } : {}) };
    }

    private async post<T>(path: string, body: Record<string, unknown>, authorization?: string, capabilities?: readonly string[]): Promise<T> {
        const url = routeUrl(this.mount, path);
        const encoded = JSON.stringify(body);

        return call<T>(this.fetchImpl, url, { method: "POST", body: encoded, headers: { Authorization: authorization ?? (await this.credential("POST", url, encoded, capabilities)) } });
    }

    private async get<T>(path: string): Promise<T> {
        const url = routeUrl(this.mount, path);

        return call<T>(this.fetchImpl, url, { method: "GET", headers: { Authorization: await this.credential("GET", url) } });
    }

    /** The bearer for a call: a request JWT for its exact URL and body when the agent has a key, else its access token. */
    private async credential(method: string, url: string, body?: string, capabilities?: readonly string[]): Promise<string> {
        if (this.options.accessToken !== undefined) {
            return `Bearer ${this.options.accessToken}`;
        }
        if (this.options.key === undefined) {
            throw new Error("The agent has no key and no access token; give it one of them.");
        }
        const jwt = await requestJwt(this.options.key, this.requireAgentId(), method, canonicalUrl(url), body, {
            ...(capabilities === undefined ? {} : { capabilities }),
            ...(this.options.jwtTtl === undefined ? {} : { ttl: this.options.jwtTtl }),
            ...(this.options.now === undefined ? {} : { now: this.options.now }),
        });

        return `Bearer ${jwt}`;
    }

    private requireAgentId(): string {
        if (this.agentId === undefined) {
            throw new Error("The agent is not registered yet: register or enroll it, or give its agentId.");
        }

        return this.agentId;
    }
}
