# Cookie token delivery — working folder

`auth.flows.token_delivery: cookie` is documented in `docs/auth/` and validated by `AuthConfig`, but nothing reads it in 0.11. This folder makes it real: the refresh token in an `HttpOnly; Secure; SameSite=Strict` cookie, a CSRF guard on every route that sets or uses it, and the client support.

| File | Read when |
|---|---|
| `spec.md` | Before starting. What 0.11 does, the design (the `session` key, the middleware, the cookie, the guard), the tests, the work package and the owner's questions. |
| `decisions.md` | Whenever a choice is made that the spec left open. Append, never rewrite. |

Branches: `cookie-mode/spec` (this folder), then `cookie-mode/wp1`.
