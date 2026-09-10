# @polaris-auth/client

The TypeScript client for [Polaris for PHP](https://github.com/univeros/polaris-core), generated from
the route manifest: `openapi-fetch` typed by the 52 endpoints, so a request body, its `data` and its
`error` are checked at compile time against the same contract the PHP hosts serve.

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

Response types come from each endpoint's `output.example` in the manifest (JSON Schema by example,
`docs/adapters/spec.md` §7): a documented approximation, exact for the shapes the specs show. Error
bodies are `ErrorBody` (`{ error, message }`) and `ValidationErrorBody` (`{ errors }`).

## Development

```sh
npm ci
npm run generate     # php ../../bin/polaris manifest --format=openapi > openapi.json; openapi-typescript → src/schema.d.ts
npm run typecheck
npm test             # starts examples/slim (installed and set up) and runs register → verify → login → me
```

`openapi.json` and `src/schema.d.ts` are checked in; CI regenerates them and fails on a difference, so a
manifest change ships with its types. `POLARIS_URL=http://host:port npm test` runs the test against a
server you started. Node 20 or later.

## License

MIT.
