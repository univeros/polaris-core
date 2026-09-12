import createOpenApiClient, { type Client, type ClientOptions } from "openapi-fetch";
import { admin, type AdminApi } from "./admin.js";
import { audit, type AuditApi } from "./audit.js";
import { challengeRetry, type ChallengeOptions } from "./challenge.js";
import { sentinel, type SentinelApi } from "./sentinel.js";
import { scim, type ScimApi } from "./scim.js";
import { sso, type SsoApi } from "./sso.js";
import type { components, paths } from "./schema.js";

export type { components, operations, paths } from "./schema.js";
export { admin, type AdminApi } from "./admin.js";
export { audit, type AuditApi } from "./audit.js";
export { challengeRetry, type ChallengeOptions } from "./challenge.js";
export { sentinel, type SentinelApi } from "./sentinel.js";
export { scim, type ScimApi } from "./scim.js";
export { sso, type SsoApi } from "./sso.js";

/** The `{ error, message }` envelope every non-2xx response of a core route carries. */
export type ErrorBody = components["schemas"]["Error"];
/** The `{ errors: [...] }` envelope of a core route's 422. */
export type ValidationErrorBody = components["schemas"]["ValidationError"];
/** The RFC 9457 problem document every non-2xx response of a plugin route (`audit`, `admin`, `sentinel`, `sso`, `scim`) carries. */
export type ProblemBody = components["schemas"]["Problem"];

export interface PolarisClientOptions extends ClientOptions {
    /** Where Polaris is mounted: `https://app.example.com`, or `https://app.example.com/api/auth` behind a prefix. */
    baseUrl: string;
    /** Sent as `Authorization: Bearer` on every request: an access token, the `mfa_token` for the MFA gate, or an admin API key (`pak_...`). */
    token?: string | null;
    /**
     * How to answer a `polaris/sentinel` challenge: with `captcha`, a `403 sentinel/challenge_required`
     * with `challenge: captcha` asks it for a token and retries the request once with `captcha_token`
     * in the body. Without it the problem document is returned as any other error.
     */
    challenge?: ChallengeOptions;
}

export interface PolarisClient extends Client<paths> {
    /** The token this client sends; null when anonymous. */
    readonly token: string | null;
    /** The `polaris/audit` routes: `client.audit.me()`, `organization()`, `types()`. */
    readonly audit: AuditApi;
    /** The `polaris/admin` routes for an operator (an admin user's token or an API key): `client.admin.listUsers()`, ... */
    readonly admin: AdminApi;
    /** The `polaris/sentinel` operator routes: `client.sentinel.listDecisions()`, `listIpRules()`, `createIpRule()`, `deleteIpRule()`, `unblock()`. */
    readonly sentinel: SentinelApi;
    /** The `polaris/sso` routes: `client.sso.signIn()`, `exchange()`, the organization's providers and domains, the operators' list. */
    readonly sso: SsoApi;
    /** The `polaris/scim` routes: the organization's connections, the operators' list, and the SCIM server itself for a directory client. */
    readonly scim: ScimApi;
    /** A new client on the same options bound to another token (null for anonymous); this one is unchanged. */
    withToken(token: string | null): PolarisClient;
}

/**
 * An `openapi-fetch` client typed by `paths` (generated from `polaris manifest --format=openapi`), so
 * `client.POST("/auth/login", { body })` checks the body and types `data` and `error`; the plugins' routes
 * are also methods of `client.audit`, `client.admin`, `client.sentinel`, `client.sso` and `client.scim`; `challenge.captcha`
 * answers a sentinel captcha challenge with one retry. No refresh loop and no storage: when to refresh
 * and where to keep tokens is the application's policy.
 */
export function createClient(options: PolarisClientOptions): PolarisClient {
    const { token = null, challenge, ...clientOptions } = options;
    const client = createOpenApiClient<paths>(clientOptions);
    if (challenge !== undefined) {
        client.use(challengeRetry(challenge));
    }
    if (token !== null) {
        client.use({
            onRequest({ request }) {
                request.headers.set("Authorization", `Bearer ${token}`);
                return request;
            },
        });
    }

    return {
        ...client,
        token,
        audit: audit(client),
        admin: admin(client),
        sentinel: sentinel(client),
        sso: sso(client),
        scim: scim(client),
        withToken: (next: string | null) => createClient({ ...options, token: next }),
    };
}
