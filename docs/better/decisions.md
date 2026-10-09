# Decisions log (program 4, "Better Auth for PHP")

Append one entry per decision. Format: date, work package, decision, reason, alternatives rejected.
Program 1's log is `../extraction/decisions.md`, program 2's `../adapters/decisions.md`, program 3's
`../plugins/decisions.md`. The defaults the spec applies before any WP opened are its §9; they become
entries here when a WP confirms or changes them.

## Log

- 2026-10-09 · spec · Program 4 is ten plugins, two agent SDKs and the developer surface in this
  repository; no new repository; core's 52 routes stay frozen; identifiers are side tables (program 3,
  WP0); ids are UUID v7. · Rejected: a `polaris/better` meta-package (nothing to put in it that
  `polaris init --plugins` does not do); a separate `polaris-agents` repository (it is a plugin like the
  six before it).
- 2026-10-09 · WP1 · Four packages, `polaris/passwordless`, `polaris/username`, `polaris/anonymous` and
  `polaris/multi-session`, each a plugin in `packages/<id>` with its specs in `api/<id>/`; the routes keep
  the spec's paths (`/magic-link/*`, `/email-otp/*`, `/phone/*`, `/one-time-token/*`, `/username/*`,
  `/anonymous/*`, `/multi-session/*`). Zero core change: sessions open through `TokenService::issue` as
  `polaris/sso` does, identifiers live in side tables. The side tables follow the plugin naming rule
  (`polaris_<plugin>_<thing>`): `polaris_passwordless_phone` and `polaris_multi_session_device` rather
  than the spec's `polaris_phone` and `polaris_device` (the latter would also read as sentinel's). ·
  Rejected: one `polaris/passwordless` holding username and anonymous (the migration map is one package
  per Better Auth plugin).
- 2026-10-09 · WP1 · `amr` names the method: `magic_link`, `email_otp`, `phone`, `anonymous`; a username
  sign-in is core's password path (`pwd`). A one-time token transfers a session rather than
  authenticating anyone, so the new session inherits the generating session's `amr`, `mfa`, `auth_time`
  and organization, and a token without a session (`sid`, so an impersonation token) cannot generate
  one. · Rejected: RFC 8176 values (`sms`, `otp`) that would make the last-login method ambiguous.
- 2026-10-09 · WP1 · Passwordless sign-ins respect core's MFA gate: a user with a confirmed factor gets
  core's `mfa_required` envelope (the `login_mfa` ticket from `MfaLoginService::beginChallenge`) instead
  of a session, and completes it at core's `/auth/mfa/verify`, whose session carries core's
  `amr: ["pwd","otp"]` because that route is frozen. `respectMfa: false` turns the gate off. One-time
  tokens skip it (the session was already authenticated). · Rejected: opening a session past the gate
  (whoever takes over the mailbox or the phone would skip the TOTP the user enrolled); minting the second
  step in the plugin (a second MFA path beside core's).
- 2026-10-09 · WP1 · Magic link and email OTP sign up an unknown email by default (`signUp: true`): the
  user is created verified and without a password, as `polaris/sso` provisions, and no `UserRegistered`
  is emitted (core's notification listener would send a verification mail the link made pointless); a
  sign-in that proves the mailbox of an unverified user verifies it (`UserEmailVerified`). With
  `signUp: false` an unknown email receives nothing and the response is the same. A phone is never a
  sign-up identifier (spec §9.3).
- 2026-10-09 · WP1 · One secrets table for the four methods (`polaris_passwordless_secret`: kind,
  identifier hash, user, secret hash, attempts, data, expiry, use). Secrets are keyed hashes under the
  pepper with one context per kind; a secret is spent by an update conditioned on `used_at IS NULL`, so
  two concurrent verifies cannot both win; an OTP is 6 digits, 5 minutes, 5 attempts; a magic link 15
  minutes; a one-time token 3 minutes. The magic link's hand-off code is 60 seconds in the cache, as
  sso's. Every send answers the same `202` for known and unknown identifiers; a wrong code and an
  unknown identifier answer the same `passwordless/code_invalid`.
- 2026-10-09 · WP1 · The magic link points at `baseUrl` + `/magic-link/verify`; the verify redirects
  only to an allow-listed `redirect_uri` (exact match, the first by default, as sso), with `code=`. An
  unknown or spent token answers a problem document rather than a redirect, because the redirect target
  is not known for it.
- 2026-10-09 · WP1 · Sentinel guards the new routes through its existing `routes` option: each plugin
  exports `SENTINEL_ROUTES` (path => attempt kind) for the host to merge into
  `new SentinelPlugin(routes: SentinelMiddleware::ROUTES + PasswordlessPlugin::SENTINEL_ROUTES + ...)`.
  Rate limits reuse core's groups: sends `mfa_send`, verifies `token_consume`, username sign-in `login`,
  anonymous sign-in `register`. · Rejected: sentinel discovering routes by tag (a sentinel change for
  what configuration already does).
- 2026-10-09 · WP1 · Username uniqueness is a normalized (lowercased) column with a unique index, the
  display form kept beside it, so case-insensitivity holds on PostgreSQL, MySQL and SQLite without
  collations. `/username/sign-in` resolves the username (or an email) and calls core's `LoginService`, so
  lockout, the MFA gate and the envelope are core's; an unknown username still runs the dummy verify
  through a non-existent address, keeping the timing parity.
- 2026-10-09 · WP1 · A guest is a core user with the placeholder email `<id>@anonymous.invalid`
  (RFC 2606), no password, unverified, plus a `polaris_anonymous` row. Conversion is explicit:
  `POST /anonymous/convert` with the guest's bearer and the access token of the account the guest just
  signed into or up, by any method; the plugin records `converted_user_id`, calls the host's
  `onConvert(guestId, userId)`, ends the guest's sessions and disables it, so the guest's id stays
  reachable for the host's data. `anonymous:prune` deletes unconverted guests older than `pruneAfter`
  (30 days) with their core rows. · Rejected: converting inside other plugins' sign-in paths (every
  method would need to know about guests).
- 2026-10-09 · WP1 · Multi-session tracks devices from the responses: the plugin's middleware (the WP2
  seam of program 3) records every response that carries a new token pair (any sign-in method, a
  refresh) against the device, with the session's `amr`, `mfa`, `auth_time` and organization. The
  device id is minted by the server and only a known id is accepted back (a client-chosen id would let
  an attacker attach a session to a victim's device and switch into it); it travels as the HttpOnly
  cookie `polaris_ms_device` and the `X-Polaris-Device` header. `switch` opens a new session for the
  target account with the stored authentication facts and revokes the old one; list, switch and revoke
  need a bearer whose session is on the device; `GET /multi-session/last-method` is public and carries
  no personal data. · Rejected: a hook in each sign-in path; the client keeping every refresh token
  (still possible; the device record is what pre-selects the button).
- 2026-10-09 · WP1 · Fixtures: core's test normaliser masks a `code=` in a Location header (it masked
  `sso_code=` only) and the `X-Polaris-Device` value, both minted per run. The multi-session fixtures run
  with the cookie off, because the hosts re-serialise `Set-Cookie`; the header path is replayed through
  the four hosts and the cookie path is unit-tested. The client generator camel-cases a plugin id
  (`multi-session` becomes `client.multiSession`).
- 2026-10-09 · WP1 · The multi-session device row keeps only the device (a SHA-256 of the server-minted
  id, 256 random bits), the account, its current session, the method of its last sign-in and a UUID v7
  minted at each sign-in (sign-ins in the same second still order; the timestamp alone tied). The
  authentication facts a switch reuses (`amr`, `mfa`, `auth_time`, organization) are read from core's
  session row, which has stored them since #97, instead of being copied. A switch ends the target's old
  session (`rotated`) and leaves the caller's; a refresh keeps `last_method` and `signed_in_at`, a switch
  too. Rows whose session ended are dropped when the device is listed. · Rejected: copying the facts onto
  the device row (two sources for one fact); ordering by `signed_in_at` (ties in the same second).
- 2026-10-09 · WP1 · Device rows of sign-ins whose client never sends the device id back are not pruned by
  the plugin; they are bounded by the sessions opened and are dropped once the device lists. A prune
  command waits until a host reports the table growing. · Rejected: recording only when the request
  carries a device (a first sign-in would never get one).
- 2026-10-09 · WP1 · Anonymous: `onConvert` runs before anything is recorded, so a failing hook converts
  nothing and the guest can retry; `POST /anonymous/sign-in` answers `201`; `anonymous:prune` deletes a
  guest's rows table by table in a transaction (sessions, factors, challenges, recovery codes,
  verifications, resets, the user, the guest row) and dispatches core's `UserDeleted` with actor `system`,
  so the host's listeners drop what they kept. Sentinel judges the guest sign-in as a `sign_up`. ·
  Rejected: core's `UserAdminService::anonymize` (it keeps a tombstone; an unconverted guest has nothing
  worth one).
- 2026-10-09 · WP1 · `PasswordlessPlugin::SENTINEL_ROUTES` guards the three public sends and `/phone/add`
  as `otp_send` and the two code sign-ins as `sign_in`; the verify-email and reset-password code routes
  stay core-rate-limited only (`token_consume`), as core's own link routes are not in sentinel's list. A
  phone confirmation by another user than the one who asked spends the code (a code proves the phone
  once). The sentinel coverage of all three plugins' constants is one test in passwordless's
  `PluginTest`, through the PSR-15 pipeline with an IP block rule.
- 2026-10-09 · WP1 · Username uniqueness is proven by `packages/username/tests/UniquenessTest.php`, a
  `DatabaseTestCase` that runs on whatever `DB_CONNECTION` selects (SQLite by default, PostgreSQL in CI)
  and forces a second writer between the lookup and the insert; it was run locally on SQLite, PostgreSQL
  16 and MySQL 8.4 (throwaway containers). Core's test normaliser masks `code=` and `sso_code=` only as a
  query parameter (`[?&]`), and the client drift check in CI covers every generated file under `src/`
  rather than the first two namespaces.
- 2026-10-09 · WP1 · Security review of the four packages (before the PR), fixed: (1) device fixation in
  multi-session: a sign-in that joins a device with accounts gets the device a new id, so an id planted in
  a victim's browser stops naming the device the victim signs into (the planted id answers
  `device_unknown`; only the browser holding the new id lists both accounts); (2) a code's attempt is
  reserved by an update conditioned on `attempts < max` with an atomic increment, so parallel guesses
  cannot exceed the budget; (3) a code sent again inherits the attempts of the live one it replaces
  (after five wrong guesses the address waits until that code expires); (4) account pre-hijacking: a
  passwordless sign-in that proves the mailbox of an unverified user clears the password set at
  registration (core's own verify-email link and the `verify-email` code keep it, as core does); (5) a
  one-time token dies with its generating session; (6) the anonymous conversion claims the guest row
  (`converted_at IS NULL`) before the hook and releases it when the hook throws; (7) `/phone/add` and
  `/phone/confirm` are `step_up` routes. · Rejected: an explicit add-account flow carrying the current
  bearer (a client change for what rotating the id does); a `__Host-` cookie (the rotation already
  defeats a tossed cookie, and the prefix would break plain-http development).
- 2026-10-09 · WP1 · Kept from the review, as residual risks matching core or sso: a send to a known
  address does more work than to an unknown one (as core's forgot-password; a queued messaging outbox
  hides it); the hand-off code is read then deleted from the PSR-16 cache, which has no atomic take (as
  sso's); the magic link is a GET that mail scanners may spend and whose code is not bound to the browser
  that asked (the spec's flow, Better Auth's too); a switch emits no `UserLoggedIn` (it is not a sign-in);
  guest sign-in is bounded by the `register` rate limit and sentinel.
