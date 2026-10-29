# Cookie token delivery — working specification v0.2

**Repository:** `github.com/univeros/polaris-core`, `docs/cookie-mode/`.
**Status:** Draft 2 — 2026-10-28, for the owner's review (§8).
**Baseline:** `main` at 0.11.0.
**Outcome:** `auth.flows.token_delivery: cookie`, documented since 1.0 (`docs/auth/flows.md`, `security.md` §3) and validated by `AuthConfig`, does what the documents say: every route that opens or rotates a Polaris session puts the refresh token in an `HttpOnly; Secure; SameSite=Strict` cookie instead of the JSON body, and every request that can set or use that cookie is guarded against CSRF. Body mode, the default, does not change by a byte.

This document is written to be executed by an engineer or a coding agent. The work package (§7) has acceptance criteria that can be checked mechanically. Decisions the spec leaves open go into `docs/cookie-mode/decisions.md`, append only.

---

## 0. Ground rules

1. **Body mode is frozen.** With `token_delivery: body` (the default) the pipeline is the one 0.11 runs: the cookie middleware (§2.3) is not even registered. The 184 core fixtures and every package's fixtures replay unchanged through the four hosts.
2. **Only the refresh token moves.** The access token stays a short-lived bearer value the client keeps in memory and sends as `Authorization: Bearer`. The refresh is therefore the only request a cookie authenticates; the CSRF guard also covers the routes that set the cookie (§2.5).
3. **No endpoint class changes.** The token moves in one PSR-15 middleware in `polaris/psr15`, which every host already runs (`Pipeline::handle()` in Slim, the Laravel, Symfony and Yii controllers, and `univeros/polaris`'s `PolarisMiddleware`). `polaris/mcp`'s `Dispatcher` also builds a `Pipeline`, in process, and stays in body mode (§2.11). Token minting, rotation and reuse detection (`TokenService`) are not touched (AGENT.md rule 7).
4. **Same bar as before.** `composer qa` green, endpoints declared in YAML (rule 6), no `Altair\`, `Cycle\` or `Univeros\` import (rule 3), decisions appended to `decisions.md`.

---

## 1. What exists in 0.11

- `AuthConfig` validates `flows.token_delivery` (`body | cookie`) and stores it in `$tokenDelivery`. Nothing reads that property.
- Fourteen routes answer a token pair with `data.refresh_token` in the body (§2.2); the endpoint or service builds the array directly. The redirecting steps before some of them (`GET /magic-link/verify`, the social and SSO callbacks) answer a one-time code, not tokens.
- `POST /auth/token/refresh` reads `refresh_token` through `Input`, which merges route parameters, the parsed body, the cookies and the query, later sources overriding earlier ones (`Input::fromServerRequest()`). A `refresh_token` in the query wins over one in the body.
- Slim's `addBodyParsingMiddleware()` and the Laravel adapter's request conversion both parse `application/x-www-form-urlencoded` bodies, so a plain HTML form can post to any route. In body mode that is harmless (the attacker cannot read the response); a response that sets a cookie changes that (§2.5).
- The documents promise "the framework `CsrfMiddleware`" for cookie mode. That is the Univeros class `Altair\Http\Middleware\CsrfMiddleware`: a `_csrf` form field checked against a PHP session, injected into server-rendered HTML forms. It cannot be imported here (rule 3) and does not fit a JSON client.
- `security.md` §9 says the module refuses to set auth cookies over plaintext; `security.md` §11 still has "CSRF guarded in cookie mode" unticked.
- One cookie exists already: `polaris/multi-session`'s `DeviceMiddleware` sets `polaris_ms_device` (`Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax`, `Secure` only over https) with `withAddedHeader('Set-Cookie', ...)`. It identifies a device, not a session, and is read on every route, hence `Path=/` and `Lax`. The refresh cookie is a credential and gets the narrow attributes of §2.4.
- `DeviceMiddleware` recognises a new session by `data.refresh_token` in the response body.
- `polaris/mcp`'s `Dispatcher` runs each tool call as an in-process request through its own `Pipeline`, and `ManifestTools` makes every public route a tool, the sign-in routes and the refresh among them.
- The manifest `Loader` ignores keys it does not know; `schema.json` does not forbid them.
- `TokenService::refresh()` claims a rotation with a compare-and-swap; the loser of two concurrent presentations of one secret takes the replay path and revokes the family. With one cookie shared by every tab, two tabs refreshing at once would sign the user out (§2.8). With `refresh_token.rotation` off, a refresh answers the presented secret again.

---

## 2. Design

### 2.1 What a host gets

A browser application on the same origin as Polaris signs in, receives the access token in the body and the refresh token as a cookie it cannot read, refreshes by posting an empty body with one header, and signs out. An injected script can still use the session while the page is open, but it can no longer take a long-lived credential away.

An application on another origin of the same site (`app.example.com` calling `auth.example.com`) also works, but only when the host adds a CORS layer: Polaris answers no `OPTIONS` preflight and sends no CORS headers. That layer must allow credentials and the `X-Polaris-CSRF` header for exactly the origins in `flows.cookie.trusted_origins` (§3), and the application passes `credentials: "include"` (§2.9).

### 2.2 Which routes: the `session` key

A new optional key in the endpoint spec, `endpoint.session`, declares what a route does to the caller's session. The YAML stays the router (rule 6), plugins declare their own routes, and the OAuth provider's `POST /oauth2/token`, whose refresh token belongs to an OAuth client and must stay in the body (RFC 6749), is untouched simply by not carrying the key.

| `session` | Routes |
|---|---|
| `issue` | core `POST /auth/login`, `POST /auth/mfa/verify`; `polaris/username` `POST /username/sign-in`; `polaris/anonymous` `POST /anonymous/sign-in`; `polaris/multi-session` `POST /multi-session/switch`; `polaris/passkey` `POST /passkey/authenticate/verify`; `polaris/passwordless` `POST /magic-link/exchange`, `POST /email-otp/verify`, `POST /phone/verify`, `POST /one-time-token/verify`; `polaris/social` `POST /social/exchange`, `POST /social/google/one-tap`; `polaris/sso` `POST /sso/exchange` |
| `refresh` | core `POST /auth/token/refresh` |
| `end` | core `POST /auth/logout`, `POST /auth/logout-all`; `polaris/sso` `POST /sso/logout` |

`schema.json` gains `"session": { "enum": ["issue", "refresh", "end"] }`; `EndpointSpec` gains `public ?string $session = null`; `Loader` reads and validates it. `polaris manifest` and the OpenAPI document carry it (as `x-polaris-session` on the operation). Adding the key changes no response in body mode.

**Version skew.** Because an older `Loader` ignores the key and a route without it is untouched, a host running the new core in cookie mode with a plugin released before this change would get that plugin's refresh token in the body, silently. Two things close that:

- `polaris/core`'s `composer.json` declares `conflict` on every plugin that carries an `issue` route (`polaris/username`, `anonymous`, `multi-session`, `passkey`, `passwordless`, `social`, `sso`) below the release that marks it.
- A coverage test walks the manifest of core and every plugin: a route whose `output.example` has `data.refresh_token` either has `session: issue | refresh` or is on an explicit list of exceptions, which holds `POST /oauth2/token` alone. A future plugin that forgets the key fails the build.

### 2.3 The middleware

`Polaris\Psr15\Middleware\RefreshCookieMiddleware`, added by `Pipeline::middleware()` only when `token_delivery` is `cookie`, right after `AuthRateLimitMiddleware`:

- after it, so a request the middleware refuses still spends the route's per-IP budget;
- before `MfaTokenMiddleware`, `TokenAuthenticationMiddleware` and every plugin's middleware, so they see requests and responses exactly as body mode produces them. `DeviceMiddleware` keeps reading `data.refresh_token` from the body; the cookie middleware removes it on the way out.

It does nothing on a route without `session`. On a marked route:

| `session` | Before the handler | After the handler |
|---|---|---|
| `issue` | refuse plaintext (§2.6); run the CSRF guard (§2.5) | on 200 or 201 with a string `data.refresh_token`: remove the key, re-encode the body, add the cookie (§2.4). Anything else (an `mfa_required` ticket, an error) passes unchanged. |
| `refresh` | refuse plaintext; run the CSRF guard; then, if no input source carries `refresh_token` (`Input` sees neither the parsed body nor the query holding one) and the request carries the cookie, put the cookie's value into the parsed body as `refresh_token` | on 200: as `issue`. On 401: clear the cookie, but only when the cookie was the credential. A failed refresh with a token from the body leaves a valid cookie alone. |
| `end` | — | on 2xx: clear the cookie. |

Details the implementation must hold to:

- The cookie is read from `getCookieParams()`, which is what every host populates (the Laravel and Symfony bridges build it from their own cookie bag, not from the `Cookie` header).
- `Set-Cookie` is added with `withAddedHeader()`, never `withHeader()`: `DeviceMiddleware`, inside this one, may already have added `polaris_ms_device`.
- The body is re-encoded the way `Polaris\Psr15\JsonResponse` encodes it, and `Content-Length` is dropped or recomputed. The removed key is removed, not set to null.
- **Error envelope.** A refusal (`csrf_failed`, `insecure_transport`) answers in the envelope of the route it refuses: `{"error", "message"}` on a core route, the RFC 9457 problem document `Endpoint::problem()` builds (`type` under `https://polaris.univeros.io/problems/`, plus `error` and `message`) when `EndpointSpec::$plugin` is set. The client's `ErrorBody` and `ProblemBody` types stay true for every route (§8, question 9).

### 2.4 The cookie

```
Set-Cookie: __Secure-polaris_refresh=<secret>; Path=<prefix>/auth/token/refresh; Max-Age=<refresh_token.ttl>; HttpOnly; Secure; SameSite=Strict
```

- **Name.** `__Secure-polaris_refresh`. The `__Secure-` prefix makes the browser reject it unless it is `Secure` and set from HTTPS. `__Host-` is not used because it requires `Path=/`.
- **Path.** The refresh route's full path as the router mounts it: `rtrim($pathPrefix, '/') . '/auth/token/refresh'`, with the prefix the `Pipeline` was built with (`Config::$pathPrefix` in the Laravel, Symfony and Yii adapters). The browser sends the cookie to the refresh and nowhere else, so no other route sees it. Logout needs no cookie: it ends the session named by the access token's `sid`.
- **Max-Age.** `refresh_token.ttl`. The server keeps the real expiry (sliding, `max_lifetime`); a cookie that outlives its token gets a 401 and is cleared. With rotation off the refresh answers the same secret and the cookie is simply set again.
- **No `Domain`.** Host-only.
- **Clearing** is the same name, path and attributes with an empty value and `Max-Age=0`.

### 2.5 The CSRF guard

In cookie mode the guard runs on every request to an `issue` or `refresh` route, before the handler, whatever carries the credential. All three must hold, or the answer is 403 `csrf_failed` (§2.3 for the envelope), the handler is not called and nothing is consumed:

1. The request carries `X-Polaris-CSRF: 1`. A cross-origin page can only send a custom header after a CORS preflight, and Polaris answers none. A host that adds its own CORS layer must not allow this header from an origin outside `trusted_origins`.
2. If `Origin` is present, it equals the request's own origin (scheme, host and port of the request URI) or one of `flows.cookie.trusted_origins`. `Origin: null` fails.
3. If `Origin` is absent and `Sec-Fetch-Site` is present, it is `same-origin`.

**Why the routes that set the cookie are guarded too.** A browser accepts a `SameSite=Strict` cookie from the response to a cross-site top-level navigation, and an HTML form POST is one. Unguarded, a page on any site could post the attacker's own credentials to `/auth/login` (form-encoded bodies are parsed, §1) and plant the attacker's refresh cookie in the victim's browser; the victim's application would then refresh into the attacker's account and type its data there (login CSRF). The same works through the refresh route with the attacker's refresh token in the form or in the query. The guard closes both, and it costs a cookie-mode client nothing, since that client sends the header anyway (§2.9).

`SameSite=Strict` still keeps the cookie off cross-site requests; the guard covers what it does not: a same-site sibling origin, cookies set by a cross-site navigation, and browsers that do not enforce it.

One consequence: Google One Tap's redirect mode (`ux_mode: redirect`, a form POST from Google's origin) is refused in cookie mode. `POST /social/google/one-tap` is specified for the JavaScript callback, which posts from the page and passes.

The request's own origin, like its scheme (§2.6), is the host's: behind a proxy that changes the host or port, the host's trusted-proxy handling must give the request its public URI.

### 2.6 Plaintext

On an `issue` or `refresh` route in cookie mode, a request whose URI scheme is not `https` gets 403 `insecure_transport` before the handler runs, so no session is created that the client could not receive. The scheme is the host's: behind a TLS-terminating proxy, the host's trusted-proxy handling must give the request an `https` URI (Laravel, Symfony and Yii do this from their own configuration; a Slim host does it in its own middleware). This is the refusal `security.md` §9 already describes.

### 2.7 Ending sessions

`end` routes clear the cookie on success. A session that ends another way (password reset's logout-all, an admin revoke, `DELETE /auth/sessions/{id}` on the caller's own session, `polaris/multi-session` revoke, a SAML single logout) leaves a cookie whose token is dead; the next refresh answers 401 and clears it.

A browser holds one refresh cookie, so every sign-in replaces the previous session's cookie. Two flows notice:

- `polaris/multi-session`: the other accounts on the device stay signed in server-side and are reached through `POST /multi-session/switch`, which is an `issue` route and sets their cookie.
- `polaris/anonymous`: signing in to the real account replaces the guest's cookie, so `POST /anonymous/convert` must run while the guest's access token is still valid (it is short-lived; the client converts right after the sign-in).

### 2.8 Tabs refreshing at once

No change to `TokenService`: the compare-and-swap and reuse detection stay exactly as they are (rule 7). The client serialises refreshes instead (§2.9): one refresh at a time per browser profile, through the Web Locks API, so a second tab waits for the first and then refreshes with the cookie the first one received.

### 2.9 The TypeScript client

`@polaris-auth/client` keeps its rule (no refresh loop, no storage) and gains:

- `createClient({ tokenDelivery: "cookie", ... })`: the client sends `X-Polaris-CSRF: 1` on every request (the guard needs it on every `issue` and `refresh` route, and it is harmless elsewhere), and leaves `credentials` at the `fetch` default (`same-origin`); a host on a trusted origin passes `credentials: "include"` itself.
- `refreshSession(client)`: posts `{}` to `/auth/token/refresh` inside `navigator.locks.request("polaris:refresh", ...)` when the API exists (one in-flight promise per tab otherwise), and returns the response as `client.POST` does.
- The generated types mark `data.refresh_token` optional on routes whose spec has `session: issue | refresh`, and `refresh_token` optional in the refresh request body. The generator derives this from `x-polaris-session`; the YAML keeps `refresh_token: { rules: [required] }`, which still holds server-side because the middleware fills the field from the cookie before the handler validates it.

### 2.10 What does not change

Every response in body mode; every route without `session`; `TokenService`; `polaris/oauth-provider`'s tokens; the access token's transport; `polaris_ms_device`; `Input`'s merge of cookies into request data (§8, question 7); `univeros/polaris`, which runs the same `Pipeline` and needs only its `^0.11` constraints raised.

### 2.11 In-process callers

`polaris/mcp`'s `Dispatcher` builds a `Pipeline` of its own and calls routes with an in-process request; there is no browser and no cookie jar. In cookie mode its sign-in and refresh tools would lose the refresh token into a `Set-Cookie` the dispatcher discards, or be refused as plaintext when `baseUrl` is `http`. So the pipeline it builds always runs in body mode: `Pipeline` gains a constructor argument that turns the cookie middleware off whatever the configuration says, and the `Dispatcher` passes it. An MCP client signing in through a tool gets its tokens in the body, as today.

---

## 3. Configuration

```php
'flows' => [
    'token_delivery' => 'cookie',          // body (default) | cookie, as today
    'cookie' => [
        'trusted_origins' => [],           // extra origins allowed to sign in and refresh, e.g. ['https://app.example.com']; needs the host's CORS layer (§2.1)
    ],
],
```

`AuthConfig` gains `public array $cookieTrustedOrigins = []`, each entry validated as `scheme://host[:port]` with `https` (fail fast at boot, as the other keys).

---

## 4. Documents to update

- `docs/auth/flows.md` delivery note, `security.md` §3 (token transport) and §9 (transport): the guard of §2.5 replaces "the framework `CsrfMiddleware`"; §11 ticks "CSRF guarded in cookie mode".
- `docs/auth/configuration.md`: `flows.cookie.trusted_origins`, and the CORS requirement of §2.1.
- `docs/auth/api-reference.md` and `packages/core/api/README.md`: the `session` key and what cookie mode does to the marked routes.
- `packages/psr15/README.md`, `packages/client-ts/README.md`: the middleware, `tokenDelivery` and `refreshSession()`.
- `packages/mcp/README.md`: tools always get tokens in the body.
- `CHANGELOG.md` for the release, with the new `conflict` constraints.

---

## 5. Tests

Functional tests under `packages/core/tests/Functional` (so they replay through the four harnesses), with cookie mode on, an `https` URI and `X-Polaris-CSRF: 1` unless stated:

1. Every `issue` route of §2.2 (the plugin ones in each plugin's suite): no `refresh_token` in `data`, every other field as in body mode, one `Set-Cookie` named `__Secure-polaris_refresh` with the attributes of §2.4 (compared as parsed attributes; see the harness notes below).
2. Login with a confirmed MFA factor: the `mfa_required` ticket is unchanged and sets no cookie; `/auth/mfa/verify` then sets it.
3. Refresh with the cookie: 200, a new cookie, the old secret no longer valid.
4. Refresh with the cookie and no header, with a foreign `Origin`, with `Origin: null`, with `Sec-Fetch-Site: cross-site`: 403 `csrf_failed`; a correct refresh afterwards still succeeds (the token was not consumed).
5. Login CSRF: a form-encoded `POST /auth/login` with valid credentials, a foreign `Origin` and no header: 403 `csrf_failed`, no `Set-Cookie`, no row in `auth_refresh_tokens`. A refresh with a valid `refresh_token` in the query or in a form body and no cookie, foreign `Origin`: 403, the token not consumed.
6. Body fallback: a refresh with a valid `refresh_token` in the body and the header: 200, the new secret in the cookie, not in the body. A refresh with an invalid token in the body while a valid cookie is present: 401, and the cookie is not cleared.
7. Replay of a rotated cookie: 401, the family revoked, the cookie cleared.
8. Logout, logout-all, SSO logout: the cookie cleared. With `polaris/multi-session` on, the response also keeps its `polaris_ms_device` cookie where body mode sets it.
9. Any `issue` or `refresh` route over `http`: 403 `insecure_transport`, and no row in `auth_refresh_tokens`.
10. A refusal on a plugin route (`POST /social/exchange` over `http`): a problem document; on a core route: `{"error", "message"}`.
11. `POST /oauth2/token` with `grant_type=refresh_token`: unchanged, body only.
12. `polaris/multi-session`: a cookie-mode sign-in is still recorded against the device.
13. `polaris/mcp`: in cookie mode, the login tool answers `refresh_token` in its body.
14. The coverage test of §2.2 over core and every plugin's manifest.
15. Body mode: the whole existing suite and every fixture, unchanged.

**Harness work the tests need.** None of this exists in 0.11:

- `FunctionalTestCase` builds path-only requests (no scheme). Cookie-mode tests build `https://` URIs, and the Laravel and Symfony harnesses, which convert through HttpFoundation, also set `HTTPS=on` in the server params, since HttpFoundation takes the scheme from there, not from the PSR-7 URI.
- Cookies travel as cookie params (`withCookieParams()`), which is what HttpFoundation reads and what the middleware reads; a `Cookie` header alone is ignored by both.
- Symfony re-serialises `Set-Cookie` (lower-case attributes, an added `expires`), so assertions parse the header into name, value and attributes and compare those, not the raw string.
- `FunctionalTestCase::authConfigArray()` reads only environment variables; it gains an overridable hook (like `plugins()`) so a test class can turn cookie mode on.

Client: unit tests for the header, the optional types and `refreshSession()` (lock taken, one request per call); the Playwright e2e signs in, refreshes and signs out against the Slim demo in cookie mode, and checks that no JavaScript-readable storage or `document.cookie` holds the refresh token.

---

## 6. Release

One minor release after 0.11 (the next free number when this merges), with the `conflict` entries of §2.2. `univeros/polaris` raises its `polaris/*` constraints in its own repository; nothing else there changes.

---

## 7. Work package

**Branch** `cookie-mode/wp1`, one pull request, after this spec is approved.

**Acceptance criteria**

- [ ] `session` key in `schema.json`, `EndpointSpec`, `Loader`, the manifest and OpenAPI output; the routes of §2.2 marked.
- [ ] The coverage test of §2.2 green; `conflict` entries in `polaris/core`'s `composer.json`.
- [ ] `RefreshCookieMiddleware` in `polaris/psr15`, registered only in cookie mode, at the position of §2.3; the guard on every `issue` and `refresh` request.
- [ ] `polaris/mcp`'s `Dispatcher` pipeline in body mode whatever the configuration (§2.11).
- [ ] `flows.cookie.trusted_origins` in `AuthConfig`, validated at boot.
- [ ] The harness work of §5; every test of §5 green through Slim, Laravel, Symfony and Yii.
- [ ] Body mode: 184 core fixtures and every package's fixtures byte-identical.
- [ ] `@polaris-auth/client`: `tokenDelivery`, `refreshSession()`, the optional types; unit tests and the cookie-mode e2e green.
- [ ] The documents of §4 updated.
- [ ] `composer qa` green; decisions logged.

---

## 8. Questions for the owner

Defaults are what this spec does if the answer is "fine".

1. **The `session` key** in the endpoint YAML, against a list of route names in the middleware. *Default:* the key (plugins declare their own routes; rule 6), with the coverage test and the `conflict` entries of §2.2 against version skew.
2. **The CSRF guard**: a custom header plus an `Origin` check (§2.5), against a double-submit token. *Default:* header plus `Origin`; it needs no state and no readable cookie.
3. **Body fallback on refresh in cookie mode**: a refresh that sends `refresh_token` in the body is still accepted, behind the same guard as any other cookie-mode refresh, and its new secret goes to the cookie. It does not keep a body-mode client working (that client loses the rotated token, see question 4); what it buys is migration: when a host switches to cookie mode, a browser session that still holds a body token moves into the cookie on its next refresh instead of being signed out. *Default:* accepted. The alternative is to refuse it with 422 and sign those sessions out at the switch.
4. **One mode per host.** A cookie-mode host gives no refresh token in the body to anyone, so a native app on the same host cannot sign in usefully. *Default:* accept that for now; a per-request opt-in (a request header choosing the delivery) is a later change. MCP tools are the one exception (§2.11).
5. **Plaintext refusal**: 403 `insecure_transport`, with no exception for `localhost`. *Default:* as written; local development runs behind HTTPS.
6. **Types**: `refresh_token` becomes optional in the generated types of the marked routes, which is a type-level change for body-mode TypeScript users. *Default:* do it in this minor (0.x).
7. **`Input` merges cookies into request data**, after the body and before the query, on every route. In body mode Polaris sets no cookie with a field's name (`polaris_ms_device` is not one), so nothing is exploitable today, and this spec does not depend on it (the cookie's name is not a field name). It is still a surprise for hosts: should it go in a separate change with its own entry in `docs/extraction/behaviour-changes.md`? *Default:* out of scope here.
8. **Behaviour register.** Cookie mode is opt-in and body mode is unchanged, so no entry in `docs/extraction/behaviour-changes.md`. *Default:* none.
9. **Refusal envelope** (§2.3): the envelope of the refused route, `{"error", "message"}` on core routes and a problem document on plugin routes. *Default:* as written. The alternative is a problem document everywhere: it also carries `error` and `message`, but core routes have never answered `application/problem+json`.

---

## 9. Out of scope

Cross-site deployments (SameSite=None and CORS with credentials across sites), Polaris answering CORS itself, cookie mode for the OAuth provider's clients or for MCP tools, a per-request delivery choice, a server-side grace window for concurrent rotation, and any change to `Input` (§8, question 7).
