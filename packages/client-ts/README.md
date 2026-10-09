# @polaris-auth/client

The TypeScript client for [Polaris for PHP](https://github.com/univeros/polaris-core), generated from
the route manifest: `openapi-fetch` typed by the 52 core endpoints and the routes of the `polaris/audit`,
`polaris/admin`, `polaris/sentinel`, `polaris/sso`, `polaris/scim`, `polaris/passwordless`,
`polaris/username`, `polaris/anonymous`, `polaris/multi-session`, `polaris/social` and `polaris/passkey`
plugins, so a request body, its
`data` and its `error` are checked at compile time against the same contract the PHP hosts serve.

```sh
npm install @polaris-auth/client
```

```ts
import { createClient } from "@polaris-auth/client";

const polaris = createClient({ baseUrl: "https://app.example.com" });   // or .../api/auth behind a prefix

const login = await polaris.POST("/auth/login", { body: { email, password } });
if (login.data && "access_token" in login.data.data) {          // a session, or an MFA ticket
    const me = await polaris.withToken(login.data.data.access_token).GET("/auth/me");
    me.data?.data.email;                                         // typed
} else if (login.error) {
    login.error.error;                                           // "invalid_credentials", ...
}
```

`createClient({ baseUrl, token, challenge, fetch, headers })` takes `openapi-fetch`'s options plus `token`,
sent as `Authorization: Bearer` on every request (an access token, or the `mfa_token` for the MFA gate), and
`challenge` (below); `withToken(token)` returns a new client bound to another token, `token: null` an
anonymous one. Nothing else: when to refresh and where to keep tokens is your application's policy. Every method of
`openapi-fetch` is there (`GET`, `POST`, `PATCH`, `DELETE`, `use` for middleware).

## The plugins

The routes a plugin adds are methods of a namespace named after the plugin, one method per endpoint
class (`ListUsersEndpoint` → `listUsers`), taking the same `openapi-fetch` init as `client.GET(path, init)`:

```ts
const operator = createClient({ baseUrl, token: "pak_..." });      // an admin API key, or an admin user's access token
const users = await operator.admin.listUsers({ params: { query: { status: "active" } } });
await operator.admin.banUser({ params: { path: { id: users.data!.data[0]!.id } } });
const trail = await polaris.withToken(accessToken).audit.me();
```

`client.audit` (`me`, `organization`, `types`), `client.admin` (users, sessions, MFA, organizations,
audit, drains, stats, keys, grants; see the package README), `client.sentinel` (`listDecisions`,
`listIpRules`, `createIpRule`, `deleteIpRule`, `unblock`), `client.sso` (`signIn`, `exchange`, `logout`,
the organization's providers and domains, the operators' list), `client.scim` (the organization's
connections, the operators' list, and the SCIM server's own routes for a directory client),
`client.passwordless` (`magicLinkSend`, `magicLinkVerify`, `magicLinkExchange`, `emailOtpSend`,
`emailOtpVerify`, `emailOtpVerifyEmail`, `emailOtpResetPassword`, `phoneSend`, `phoneVerify`, `phoneAdd`,
`phoneConfirm`, `oneTimeTokenGenerate`, `oneTimeTokenVerify`), `client.username` (`signIn`, `update`),
`client.anonymous` (`signIn`, `convert`), `client.multiSession` (`list`, `switch`, `revoke`,
`lastMethod`), `client.social` (`start`, `exchange`, `oneTap`, `accounts`, `link`, `unlink`, `token`) and
`client.passkey` (`registerOptions`, `registerVerify`, `authenticateOptions`, `authenticateVerify`, `list`,
`rename`, `delete`) are generated into `src/<plugin id>.ts` by `scripts/generate-namespaces.mjs` from the
`x-polaris-plugin` marker of the OpenAPI document; a later plugin gets its namespace the same way, its id
camel-cased (`multi-session` is `client.multiSession`). Their errors are RFC 9457 problem documents,
`ProblemBody` (`{ type, title, status, detail, error, message, errors? }`), served as
`application/problem+json`.

Response types come from each endpoint's `output.example` in the manifest (JSON Schema by example,
`docs/adapters/spec.md` §7): a documented approximation, exact for the shapes the specs show. Error
bodies are `ErrorBody` (`{ error, message }`) and `ValidationErrorBody` (`{ errors }`).

## Social sign-in

`client.social.start()` answers the provider's URL and a `state`; keep the state (`sessionStorage`), send
the browser to the URL, and on the page the sign-in ends on compare the `state` in the query with it
before exchanging the `code`:

```ts
const { data } = await polaris.social.start({ params: { path: { provider: "google" } }, body: {} });
sessionStorage.setItem("polaris.social.state", data!.data.state);
location.assign(data!.data.url);
// ...on /signed-in:
const query = new URLSearchParams(location.search);
if (query.get("state") !== sessionStorage.getItem("polaris.social.state")) throw new Error("not the flow this browser started");
const session = await polaris.social.exchange({ body: { code: query.get("code")! } });
```

## Passkeys

`registerPasskey()`, `signInWithPasskey()` and `passkeyAssertion()` run the WebAuthn ceremonies of
`polaris/passkey` in the browser (`navigator.credentials`, a secure context) over the client's routes;
they are the only hand-written code besides the sentinel retry.

```ts
import { createClient, registerPasskey, signInWithPasskey, passkeyAssertion } from "@polaris-auth/client";

const { passkey, recovery_codes } = await registerPasskey(polaris.withToken(accessToken), "MacBook");
const session = await signInWithPasskey(polaris);                         // a prompt
const autofilled = await signInWithPasskey(polaris, { conditional: true }); // the form's autofill (autocomplete="username webauthn")
// The passkey as the second factor of a password login that answered mfa_required:
await polaris.withToken(mfaToken).POST("/auth/mfa/verify", { body: { factor_id, code: await passkeyAssertion(polaris) } });
```

## Several accounts on one device

With `polaris/multi-session`, every response that carries a token pair also carries the device id in
`X-Polaris-Device` (and, for a browser, the HttpOnly cookie `polaris_ms_device`). A client that is not a
browser sends it back on the multi-session routes:

```ts
const device = signIn.response.headers.get("X-Polaris-Device")!;
const accounts = await polaris.withToken(access).multiSession.list({ headers: { "X-Polaris-Device": device } });
const other = await polaris.withToken(access).multiSession.switch({ body: { session_id: accounts.data!.data[1]!.session_id }, headers: { "X-Polaris-Device": device } });
const button = (await polaris.multiSession.lastMethod({ headers: { "X-Polaris-Device": device } })).data?.data.last_method;
```

## The sentinel challenge

With `polaris/sentinel` enforcing, a sign-up, sign-in, password reset or code send may answer `403` with
the `sentinel/challenge_required` problem and `challenge: captcha`. Give the client a way to get a captcha
token and it answers the challenge itself: the callback is asked once, and the same request is sent
again with `captcha_token` added to its body.

```ts
const polaris = createClient({
    baseUrl,
    challenge: { captcha: () => turnstile.execute() },   // the host's widget (Turnstile, hCaptcha, ...) yields the token
});
const login = await polaris.POST("/auth/login", { body: { email, password } });   // challenged, solved, answered
```

One retry only: the retried response is returned as it is, so a wrong token is one problem document
and never a loop; every other error, and the challenge when no `captcha` callback is given, is returned
as today. `withToken` keeps the callback. `challengeRetry(options)` is exported for a plain `openapi-fetch`
client (`client.use(challengeRetry({ captcha }))`).

## Development

```sh
npm ci
npm run generate     # bin/polaris manifest --format=openapi --bootstrap=polaris.php > openapi.json; openapi-typescript → src/schema.d.ts; the namespaces
npm run typecheck
npm test             # starts examples/slim (installed and set up) and runs register → verify → login → me, then the admin and audit namespaces
```

`openapi.json`, `src/schema.d.ts` and the namespaces (`src/audit.ts`, `src/admin.ts`, `src/sentinel.ts`,
`src/sso.ts`, `src/scim.ts`) are checked in; CI regenerates them and fails on a difference, so a manifest
change ships with its types. `polaris.php` is the application the client is generated for (core with the
five plugins that have routes). `POLARIS_URL=http://host:port npm test` runs the test against a server
you started. Node 20 or later. Every `v*` tag of the monorepo publishes the package to npm through
trusted publishing (`.github/workflows/npm-publish.yml`, OIDC, provenance attached, no token).

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
