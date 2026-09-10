import createOpenApiClient, { type Client, type ClientOptions } from "openapi-fetch";
import type { components, paths } from "./schema.js";

export type { components, operations, paths } from "./schema.js";

/** The `{ error, message }` envelope every non-2xx Polaris response carries. */
export type ErrorBody = components["schemas"]["Error"];
/** The `{ errors: [...] }` envelope of a 422. */
export type ValidationErrorBody = components["schemas"]["ValidationError"];

export interface PolarisClientOptions extends ClientOptions {
    /** Where Polaris is mounted: `https://app.example.com`, or `https://app.example.com/api/auth` behind a prefix. */
    baseUrl: string;
    /** Sent as `Authorization: Bearer` on every request: an access token, or the `mfa_token` for the MFA gate. */
    token?: string | null;
}

export interface PolarisClient extends Client<paths> {
    /** The token this client sends; null when anonymous. */
    readonly token: string | null;
    /** A new client on the same options bound to another token (null for anonymous); this one is unchanged. */
    withToken(token: string | null): PolarisClient;
}

/**
 * An `openapi-fetch` client typed by `paths` (generated from `polaris manifest --format=openapi`), so
 * `client.POST("/auth/login", { body })` checks the body and types `data` and `error`. No refresh loop
 * and no storage: when to refresh and where to keep tokens is the application's policy.
 */
export function createClient(options: PolarisClientOptions): PolarisClient {
    const { token = null, ...clientOptions } = options;
    const client = createOpenApiClient<paths>(clientOptions);
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
        withToken: (next: string | null) => createClient({ ...options, token: next }),
    };
}
