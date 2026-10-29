import type { Client, Middleware } from "openapi-fetch";
import type { paths } from "./schema.js";

/** The header a cookie-mode client sends on every request; the server's CSRF guard requires it on every route that sets or uses the refresh cookie. */
export const CSRF_HEADER = "X-Polaris-CSRF";

/** How the server delivers the refresh token: in the JSON body (the default) or in an `HttpOnly` cookie the client never sees. */
export type TokenDelivery = "body" | "cookie";

/** Adds `X-Polaris-CSRF: 1` to every request, for a server with `auth.flows.token_delivery: cookie`. */
export function cookieDelivery(): Middleware {
    return {
        onRequest({ request }) {
            request.headers.set(CSRF_HEADER, "1");
            return request;
        },
    };
}

function refresh(client: Client<paths>) {
    // The refresh cookie is the credential; the body is empty.
    return client.POST("/auth/token/refresh", { body: {} });
}

/** What `refreshSession()` answers: the refresh route's response, as `client.POST` answers it. */
export type RefreshSessionResult = Awaited<ReturnType<typeof refresh>>;

let inFlight: Promise<RefreshSessionResult> | null = null;

/**
 * Rotates the session in cookie mode: posts an empty body to `/auth/token/refresh`, whose cookie the
 * browser sends, and answers the new access token in `data`. Refreshes are serialised across the tabs of
 * a browser profile through the Web Locks API, so two tabs never present the same rotated cookie (the
 * server would take the second as a replay and end the session); a tab waiting for the lock refreshes
 * with the cookie the first one received. Without Web Locks, concurrent calls in one tab share one request.
 */
export function refreshSession(client: Client<paths>): Promise<RefreshSessionResult> {
    const locks = (globalThis as { navigator?: { locks?: LockManager } }).navigator?.locks;
    if (locks !== undefined) {
        // The DOM typing wraps the callback's promise once more; the runtime resolves it.
        return locks.request("polaris:refresh", () => refresh(client)).then((result) => result);
    }
    inFlight ??= refresh(client).finally(() => {
        inFlight = null;
    });

    return inFlight;
}
