# Decisions log (cookie token delivery)

Append one entry per decision. Format: date, work package, decision, reason, alternatives rejected.

## Open at start (decide before WP1)

- The owner's questions in `spec.md` §8: answered 2026-10-29, see the log.

## Log

<!-- YYYY-MM-DD · WPn · decision · reason · rejected alternatives -->
- 2026-10-29 · spec · The owner accepts every §8 default: the `session` key (1), a custom header plus an
  `Origin` check (2), the body fallback on refresh (3), one mode per host (4), plaintext refused with no
  `localhost` exception (5), `refresh_token` optional in the generated types of the marked routes (6),
  `Input`'s cookie merge out of scope (7), no behaviour-register entry (8), the refused route's own
  envelope (9). · Reasons as in §8.
- 2026-10-29 · WP1 · The client's cookie-mode e2e (§5) runs the Slim demo behind a local TLS front, not over
  plain `http://127.0.0.1:8080`: with question 5's default every `issue` and `refresh` route answers 403
  `insecure_transport` over http, and the `__Secure-` cookie needs HTTPS anyway. The test then exercises what
  production runs. · Rejected: a `localhost` exception (a second code path the e2e would prove instead of
  the real one, and a different cookie name on localhost).
- 2026-10-29 · release · Cookie mode ships as 0.12.0, before program 4's WP5, which moves to 0.13.0
  (`docs/better/spec.md` §8, logged there). · Reason: one smaller work package the owner needs now.
- 2026-10-29 · WP1 · A refusal on a plugin route is a problem document of type
  `https://polaris.univeros.io/problems/cookie/<code>` with `error` equal to the code (`csrf_failed`,
  `insecure_transport`), the same code a core route answers in `{"error", "message"}`. · Reason: a client
  checks one `error` value whatever route it called. · Rejected: the refused plugin's own prefix
  (`social/csrf_failed`), whose `error` would be `social_csrf_failed` and differ per plugin.
- 2026-10-29 · WP1 · The `conflict` entries of §2.2 land with the 0.12.0 version bump, not before: the
  monorepo resolves every package from path repositories at `0.11.x-dev`, so `<0.12` would make its own
  `composer update` fail until the version line moves. Tracked on #69's release list.
- 2026-10-29 · WP1 · The harnesses needed no `HTTPS=on` work: `symfony/psr-http-message-bridge`'s
  `HttpFoundationFactory` sets it from an `https://` URI and copies the cookie params. What remained:
  `FunctionalTestCase::authConfig()` (merged over the environment's), requests with full URIs and cookie
  params (`CookieRequests`), parsed `Set-Cookie` assertions; Laravel re-serialises `Max-Age` from its
  computed expiry, so the attribute is compared within five seconds.
- 2026-10-29 · WP1 · §5 test 1 on every plugin `issue` route is met in two layers: a unit test runs the
  middleware against every route the manifests mark (core's and every plugin's) for the guard, the
  plaintext refusal, the envelope and the move to the cookie; functional tests through the four kernels
  drive core's routes end to end and `polaris/multi-session`'s (sign-in recorded on the device, the switch,
  the device cookie beside the refresh cookie). The middleware is route-agnostic, so driving each plugin's
  sign-in ceremony (passkey, social, SSO, passwordless) in cookie mode would retest the same code path.
- 2026-10-29 · WP1 · The Slim demo gains two opt-in environment switches, `POLARIS_TOKEN_DELIVERY=cookie`
  and `POLARIS_TRUST_FORWARDED_PROTO=1` (an `https` URI for a request from 127.0.0.1 carrying
  `X-Forwarded-Proto: https`), which the client's cookie-mode e2e uses behind `e2e/tls-proxy.mjs`, a Node
  HTTPS front with a throwaway `openssl` certificate. The second is the trusted-proxy handling §2.6 leaves
  to a Slim host, as a reference. The e2e drives the browser with same-origin `fetch` the way the client
  does; the client's own code is covered by its unit tests.
