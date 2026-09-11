# @polaris-auth/client

The TypeScript client for [Polaris for PHP](https://github.com/univeros/polaris-core), generated from
the route manifest: `openapi-fetch` typed by the 52 core endpoints and the routes of the `polaris/audit`
and `polaris/admin` plugins, so a request body, its `data` and its `error` are checked at compile time
against the same contract the PHP hosts serve.

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

`createClient({ baseUrl, token, fetch, headers })` takes `openapi-fetch`'s options plus `token`, sent as
`Authorization: Bearer` on every request (an access token, or the `mfa_token` for the MFA gate);
`withToken(token)` returns a new client bound to another token, `token: null` an anonymous one. Nothing
else: when to refresh and where to keep tokens is your application's policy. Every method of
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
audit, drains, stats, keys, grants; see the package README) and `client.sentinel` (`listDecisions`,
`listIpRules`, `createIpRule`, `deleteIpRule`, `unblock`) are generated into `src/audit.ts`, `src/admin.ts`
and `src/sentinel.ts` by `scripts/generate-namespaces.mjs` from the `x-polaris-plugin` marker of the OpenAPI
document; a later plugin gets its namespace the same way. Their errors are RFC 9457 problem documents,
`ProblemBody` (`{ type, title, status, detail, error, message, errors? }`), served as
`application/problem+json`.

Response types come from each endpoint's `output.example` in the manifest (JSON Schema by example,
`docs/adapters/spec.md` §7): a documented approximation, exact for the shapes the specs show. Error
bodies are `ErrorBody` (`{ error, message }`) and `ValidationErrorBody` (`{ errors }`).

## Development

```sh
npm ci
npm run generate     # bin/polaris manifest --format=openapi --bootstrap=polaris.php > openapi.json; openapi-typescript → src/schema.d.ts; the namespaces
npm run typecheck
npm test             # starts examples/slim (installed and set up) and runs register → verify → login → me, then the admin and audit namespaces
```

`openapi.json`, `src/schema.d.ts`, `src/audit.ts` and `src/admin.ts` are checked in; CI regenerates them
and fails on a difference, so a manifest change ships with its types. `polaris.php` is the application the
client is generated for (core with the audit and admin plugins). `POLARIS_URL=http://host:port npm test` runs the test against a
server you started. Node 20 or later.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
