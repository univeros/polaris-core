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
- 2026-10-09 · WP1 · The split workflow submits a package Packagist does not know yet: when
  `update-package` answers 404 on a split's first push, it calls `create-package` with the same
  `PACKAGIST_AUTH`, so the four new packages register themselves when this PR's merge splits them. The
  four split repositories (`univeros/polaris.{passwordless,username,anonymous,multi-session}`) must exist
  and `POLARIS_SPLIT_TOKEN` must reach them first (owner). Packagist's "Legacy Auto-Update, Needs
  Attention" label on the existing packages is the API-ping path this workflow uses; it clears when the
  owner's Packagist account syncs its GitHub hooks, outside this repository.
- 2026-10-09 · WP1 · Open for the 1.0 security review: a passwordless sign-in and an MFA factor on the
  same channel (an email code or magic link, then core's email OTP factor on that address; a phone code,
  then an SMS factor on that number) pass core's gate with one channel. WP1 leaves core's gate as it is
  (it accepts any confirmed factor, and `/auth/mfa/verify` is frozen). The options: a plugin-side
  refusal of passwordless sign-in for a user whose only factors share its channel, or a core seam where
  the `login_mfa` ticket carries the factors allowed to complete it (a logged core change). TOTP and
  recovery codes are unaffected.
- 2026-10-09 · WP2 · Decision #1, the one planned core seam (spec §3.2, §9.2): a plugin adds an MFA
  factor type through two contracts, `Polaris\Contract\MfaFactorType` (`type()`, `verify(factor, code,
  purpose)`) and `Polaris\Contract\MfaFactorTypeProvider` (`mfaFactorTypes(Graph)`, implemented by the
  plugin as `CommandProvider` is), and `MfaChallengeVerifier` dispatches a factor whose type is not
  `totp`, `sms` or `email` to the registered type. Core owns the factor row (`auth_mfa_factors`, listed,
  relabelled, defaulted and removed by its own routes, the first-factor recovery codes through
  `MfaConfirmation`), the `login_mfa` ticket and the verify routes (`/auth/mfa/verify`,
  `/auth/mfa/step-up`, whose `code` carries what the type verifies, for a passkey the assertion JSON);
  the plugin owns enrolment (its own ceremony routes) and verification. `/auth/mfa/challenge` keeps
  answering `422 unsupported_factor` for a plugin type as it does for TOTP: the plugin's options route is
  the challenge. The session a plugin type completes carries core's `amr: ["pwd","otp"]`, as after a
  passwordless sign-in (the verify routes are frozen). No route, fixture or existing behaviour changes;
  the 184 core fixtures replay unchanged. · Rejected: registration on `Config` (the type needs the
  graph's services, so it would be a factory callable the host writes; the plugin already has the
  graph); a `passkey` type inside core (the plugin owns the verification, spec §3.2).
- 2026-10-09 · WP2 · `polaris/passkey`: one table `polaris_passkey` (id, user_id, credential_id,
  public_key as the COSE key, counter, aaguid, transports, backed_up, name, factor_id, last_used_at,
  created_at); the options of a ceremony live in the cache for 5 minutes keyed by the challenge, so a
  verify finds them without a session (discoverable sign-in, conditional UI) and once. A credential is a
  core factor (`factor_id`) when the plugin is configured `mfaFactor: true` (the default): registration
  creates the confirmed factor row through `MfaConfirmation`, so the first one answers recovery codes and
  `mfa.enrolled`; removing the factor through core's route keeps the passkey as a sign-in credential
  (the plugin's listener clears the link); deleting the passkey removes its factor, refused as
  `passkey/last_factor` when core's enforcement protects it. A sign-in session carries
  `amr: ["passkey"]`, and `mfa: true` with the MFA gate skipped only when the authenticator reported user
  verification (`UV`), because then the passkey is itself two factors; without `UV` core's gate applies
  as for passwordless. `DELETE /passkey/{id}` is a `step_up` route like core's factor delete. Relying
  party id and allowed origins come from the plugin's configuration; an origin or rpId the authenticator
  did not sign for is `passkey/origin_mismatch`, read from the client data before the library runs.
  Attestation is `none` (the authenticator's attestation is not verified, as Better Auth's); the
  library is `web-auth/webauthn-lib` ^5.3 behind `Polaris\Passkey\Protocol`. Tests use a software
  authenticator (P-256, `none` attestation) so the recorded fixtures carry real WebAuthn payloads.
  · Rejected: `polaris_passkey_challenge` table (the cache is what sso and passwordless use); counting
  passkeys as credentials for `social/last_credential` (couples the packages).
- 2026-10-09 · WP2 · `polaris/social`: the OAuth state lives in the cache (spec §3.1 allows it; what sso
  does), no `polaris_social_state` table. Linking starts at `POST /social/{provider}/link` (bearer,
  `step_up`), which puts the user in the state; `POST /social/{provider}/start` is public and has no
  `link` flag (a public route carries no bearer). The callback accepts `GET` and `POST` (Apple answers
  with `response_mode=form_post`). A sign-in by a trusted provider with a verified email links to the
  existing user; an untrusted provider or an unverified email refuses with `social/account_exists` and
  the user links from a session; sign-up creates a verified user without a password, `amr:
  ["social:<provider>"]`. The last credential is "no password and no other linked account", so unlinking
  it is `social/last_credential`. Provider tokens are encrypted with core's encrypter and never returned
  except by `POST /social/{provider}/token`, which refreshes an expiring one. The catalog is data
  (`Catalog`: endpoints, scopes, PKCE, OIDC issuer, profile mapping) behind one `OAuth2Provider`, with
  provider classes only where the protocol differs: Apple (client-secret JWT, `form_post`, the user from
  the id_token and the first callback), Google (One Tap), Microsoft (tenant), GitHub (a second call for
  the verified email); `GenericOAuth` is the same class on a host's own definition. `polaris/audit` is
  required (the `social.*` names join the catalog, as sso's do). · Rejected: a state table; `link: bool`
  on the public start route.
- 2026-10-09 · WP2 · The OAuth proxy: `proxy: 'https://auth.example.com'` names the stable origin
  registered at the providers. A deployment whose `baseUrl` is another origin (a preview, localhost)
  sends the provider to the stable origin's callback and puts its own callback in the state as a signed
  `return_to` (a keyed hash under core's pepper, which the deployments share); the stable origin's
  callback forwards a state carrying a validly signed `return_to` to it with the code, and refuses an
  unsigned or tampered one (`social/state_invalid`), so it is never an open redirector. The preview
  then completes the exchange itself with its own cache entry and client secret. · Rejected: a shared
  state store between deployments (nothing shared but the secrets).
- 2026-10-09 · WP2 · The factor types a plugin registers are resolved on the verifier's first use (a
  closure in `MfaChallengeVerifier`), not when the graph builds it: the passkey type is built from the
  plugin's service, which needs core's MFA login service, which needs the verifier; resolving at
  construction looped. The provider contract says so. · Rejected: forbidding a type to use the MFA
  services (the passkey type opens no session itself, but its service does for sign-in).
- 2026-10-09 · WP2 · Rate limits reuse core's groups: `/passkey/authenticate/options` is `token_refresh`
  (60 a minute per IP: a conditional-UI page mints a challenge on load and the challenge is a random
  string in the cache), `/passkey/authenticate/verify`, `/social/{provider}/start` and
  `/social/google/one-tap` `login`, the callbacks and `/social/exchange` `token_consume`, the
  registration routes `mfa_enroll` and `mfa_confirm`, `/social/{provider}/link` `mfa_enroll`. Sentinel
  guards `/passkey/authenticate/verify`, `/social/{provider}/start` and `/social/google/one-tap` as
  `sign_in` through the plugins' `SENTINEL_ROUTES`.
- 2026-10-09 · WP2 · Core's test normaliser masks `state`, `nonce`, `code_challenge` and `code` in any URL
  a body or a Location header carries (the social `start` answers the provider's authorization URL with
  per-run values; sso's `sso_code` was the only case before). A provider's scope list is split on spaces
  or commas (GitHub and Facebook answer commas). The social fixtures run the recorded providers through
  the same routing PSR-18 client sso's tests use; the four hosts replay them unchanged.
- 2026-10-09 · WP2 · The Slim demo: `src/FakeProvider.php` is the demo's own OAuth 2 server behind the
  `fake` provider (a `Definition`, as any host's server), called in-process through `LoopbackClient`
  because `php -S` serves one request at a time; the plugins' short-lived state goes to `src/FileCache.php`
  (`var/cache`) because every `php -S` request is a fresh process, while the rate limits stay in memory;
  the demo's origin is `http://localhost:8080` (an IP is not a relying party id). The Playwright run of
  spec §8 WP2.4 drives `examples/slim/public/passkey.html` from `packages/client-ts` (the repository's
  one Node project: `npm run e2e`, Chromium with a CDP virtual authenticator), after the client's tests in
  the same CI job. The walkthrough signs in through the fake provider on the Slim demo only (it probes
  `/fake-oauth/me`). · Rejected: a second Node project under `examples/slim`; Playwright talking to the
  passkey routes directly (the browser side is the point of the run).
- 2026-10-09 · WP2 · Security review of the two packages, the seam and the demo (before the PR), fixed:
  (1) account pre-hijacking through linking: a trusted provider's verified email that matches an
  unverified existing user claims that user (the password set without proving the mailbox goes, as
  after a passwordless sign-in; the sessions and the other linked accounts too) instead of linking into
  whoever registered the address; (2) a social or passkey sign-in respects core's `require_verified_email`
  (`social/email_unverified`, `passkey/email_unverified`): a sign-up through a provider that did not
  vouch for the email makes an account but no session until the email is verified; (3) the callback's
  redirect carries the `state` back with the code, so the application compares it with what `start`
  answered before exchanging (login CSRF); (4) a passkey sign-in without user verification is not offered
  its own factor as the second step: another factor gates it, and when there is none the sign-in is
  `passkey/user_verification_required`; (5) passkey registration is a `step_up` route (a passkey with
  user verification signs in past the gate, so a stolen access token must not register one), as is
  `/social/{provider}/token`; (6) both plugins delete the user's accounts and passkeys on core's
  `UserDeleted`; (7) a One Tap sign-in keeps the provider tokens a callback stored; (8) the proxy's
  signed payload names the provider and expires with the state; (9) a profile's name fits the display
  name (120 characters); (10) one provider account per user and provider (unique index); (11) a plain
  http origin for passkeys is accepted on localhost only; (12) the demo's mailbox route answers the
  loopback only. · Rejected: binding the OAuth state to a cookie (the API has no cookie session; the
  state comparison is the client's, as Better Auth's); rate limiting the token route beyond the
  authenticated budget (the step-up is the protection).
- 2026-10-09 · WP2 · Kept from the review, as residual risks matching sso's behaviour: the one-use reads
  of a state, a challenge and a hand-off code are a get then a delete on the PSR-16 cache (no atomic take);
  the hand-off outcome is cached as the envelope; `JWT::$leeway` is process-wide (sso sets it too); a
  colliding factor type surfaces at the first verification rather than at boot (the types are lazy);
  turning `mfaFactor` off after enrolment leaves factor rows nothing verifies (recovery codes remain);
  `start` takes the scopes it is given (within the provider's consent screen); the last-credential and
  unlink checks are not transactional. Open for the 1.0 review: a link started by one session and
  completed in another browser links the provider account to the starter (the exchange is public, as
  sso's); binding the exchange of a link outcome to the starting bearer would close it.
- 2026-10-09 · WP2 · CI pulls the Postgres service from the ECR Public mirror of the Docker official
  image (`public.ecr.aws/docker/library/postgres:16`): four consecutive runs of #48 failed on Docker
  Hub's unauthenticated pull-rate limit on the shared runner addresses before a single test ran, and a
  rerun does not clear it. The mirror serves the same image without that limit. · Rejected: a Docker
  Hub login step (a secret for a public image); waiting out the limit (hours per occurrence).
