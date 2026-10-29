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
