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
- 2026-10-09 · WP2 · CI pulls the Postgres service from Google's Docker Hub mirror
  (`mirror.gcr.io/library/postgres:16`): four consecutive runs of #48 failed on Docker Hub's
  unauthenticated pull-rate limit on the shared runner addresses before a single test ran, and a rerun
  does not clear it. The mirror serves the same image without that limit. · Rejected: a Docker Hub
  login step (a secret for a public image); waiting out the limit (hours per occurrence).
- 2026-10-10 · WP3 · Spec §9.4: `polaris/oauth-provider` is written fresh behind the plugin contract, not
  `league/oauth2-server`: the library's repository interfaces fight the plugin schema contract (it
  wants its own entities and storage for clients, scopes, codes and tokens), its entity model duplicates
  core's users, and what WP3 adds on top (DPoP, CIBA, token exchange, CIMD, device flow data pages) is
  not in it, so it would be an adaptation layer plus forks. `lcobucci/jwt` (core's) mints the access
  tokens with core's signing key and `kid`; `firebase/php-jwt` (sso's and social's) verifies client
  assertions and DPoP proofs from JWKs. Plugin ids: `api-keys` (`Polaris\ApiKeys\`, `api/api-keys/`,
  `client.apiKeys`, problems `api-keys/*`) and `oauth` for the `polaris/oauth-provider` package
  (`Polaris\OAuth\`, `api/oauth/`, `client.oauth` as spec §5 names it, problems `oauth/*` as §7).
  · Rejected: `league/oauth2-server` adapted to the schema contract (see above); plugin id
  `oauth-provider` (`client.oauthProvider`, problems `oauth-provider/*`, against §5 and §7).
- 2026-10-10 · WP3 · Decision #2, a core seam (spec §3.5 "the plugin middleware accepts `Authorization:
  Bearer pk_...` or `x-api-key` on every Polaris route"): a plugin middleware cannot do that, because
  core's `TokenAuthenticationMiddleware` answers 401 on every `auth: bearer` route before the plugins'
  middleware runs. So core gains `Polaris\Contract\BearerResolver` (`resolve(ServerRequestInterface):
  ?TokenInterface`, null for a request it does not recognise, `AuthorizationTokenException` to refuse
  one it does) and `Polaris\Contract\BearerResolverProvider` (`bearerResolvers(Graph)`, implemented by
  the plugin as `MfaFactorTypeProvider` is), collected by `Graph::bearerResolvers()`; psr15's
  `TokenAuthenticationMiddleware` asks the resolvers first, on `auth: bearer` routes only, and parses
  the core JWT when none answers. The seam is in the middleware, not in `TokenFactoryInterface`, so
  `polaris/admin`'s principals, scim, the host guards and every other caller of
  `tokenFactory()->fromTokenString()` keep seeing core sessions only (an API key is never an admin
  principal by accident). No route, fixture or existing behaviour changes. · Rejected: running the
  plugins' middleware before token authentication (the contract says "after the bearer token was
  parsed"); a `TokenFactoryInterface` port (one plugin at a time, and every consumer would accept keys).
- 2026-10-10 · WP3 · Decision #3, a core seam: a token that carries the metadata `delegated` (a list of
  permission names, set in-process by a bearer resolver and never read from the wire) makes
  `Gate::authority()` answer the database-resolved authority with its `scope` intersected with that
  list; roles stay (they describe the owner). Core's own access tokens never carry it. This is "the
  key's permissions intersected with the owner's" of §3.5 and "scopes = permissions" of §3.6 in one
  place; WP4's agent tokens will carry it too. · Rejected: the plugin middleware re-checking the
  route's permissions against the key (the `AUTHORITY` attribute would still carry the owner's full
  authority into the endpoints); trusting `scope` on core tokens (a behaviour change of the 52 routes).
- 2026-10-10 · WP3 · `polaris/api-keys`: one table `polaris_api_key` (owner type and id, the organization
  the key acts in, the creating member, name, environment, the secret's last four characters as `hint`,
  the keyed hash under pepper context `api_key`, permissions, rate limit, metadata, rotation and
  revocation state). A user's key acts as the user in the organization that was active when it was
  created; an organization's key (`organization_id` on create: the caller's active organization, with
  `org.update`) acts as the member who created it, in that organization, so "the key's permissions
  intersected with the owner's" is core's resolution of that member at call time (decision #3), and a
  member who leaves takes the organization's keys with them. The permissions a key is given must be
  held by the caller in that organization at creation and at every change (`api-keys/permission_not_held`)
  and exist in the permission catalog. A key is presented as `Authorization: Bearer pk_...` or
  `x-api-key`, authenticates as `amr: ["api_key"]` with `jti` = the key id and `iat` = now (a logout
  everywhere does not end a key; revocation does), has no session, and is refused on every `step_up`
  route (`403 api-keys/not_allowed`: it cannot re-authenticate, and a stolen key must not add
  credentials). Rotation mints a successor row (`rotated_from`) and gives the predecessor a
  `grace_until` (`rotationGrace`, a day); rotating a rotated key is refused. Revocation is a soft
  `revoked_at`; `DELETE` answers `{status: revoked}`. The key's own `rate_limit` is counted on
  `RateStore` under `api_keys.key.<id>` by the plugin's middleware with core's `X-RateLimit-*` headers;
  core's per-user budget applies as well. An owner holds at most `maxPerOwner` (50) live keys; the
  secret is `pk_<live|test>_` plus 256 random bits (base64url). `polaris/audit` is required
  (`api_keys.created|updated|rotated|revoked`). `POST /api-keys/verify` is for applications that proxy;
  any session may ask, the key itself being the secret, and the check counts as a use. Core's test
  normaliser masks a `hint` key. · Rejected: `/orgs/{id}/api-keys` routes (one route set with
  `organization_id` is the same surface); keys bound to a user independent of any organization context
  (such a key could do nothing core guards with a permission); an `admin`-style principal for keys
  (the whole point of decision #2 is that a key is the owner, so every endpoint already knows it).
- 2026-10-10 · WP3 · `polaris/oauth-provider` (plugin id `oauth`): six tables, `polaris_oauth_client`
  (a UUID `client_id`, so a client id in a path reads like every other id; secrets `pcs_` plus 256 bits
  as keyed hashes under pepper context `oauth_client`), `_consent` (one row per user and client, scopes
  merged), `_code` (keyed hash, spent by an update conditioned on `used_at IS NULL`, bound to the client,
  the redirect URI, the S256 challenge, the nonce and a `dpop_jkt`), `_token` (every access token by
  `jti`, every refresh token `prt_` as a keyed hash, both in a rotation family; a spent refresh token
  presented again revokes the family, RFC 9700 §4.14), `_device_code` and `_ciba_request` (status
  machines, spent once, polls throttled by `last_polled_at`). Access tokens are RFC 9068 JWTs (`typ:
  at+jwt`) minted by the plugin's own lcobucci builder with core's signing key and `kid` (core's
  generator owns `aud` and `exp`), `aud` = the `resource` asked or the issuer; the plugin's bearer
  resolver (decision #2) accepts them on every route when `aud` names this server, they are live in the
  token table and presented as bound (a `cnf.jkt` token with the `DPoP` scheme and a proof carrying
  `ath`; a bearer one with `Bearer`), as the user with `delegated` = the permission scopes (decision
  #3); a client's own token clears no permission check. Scopes are the permission catalog plus
  `openid`, `profile`, `email`, `offline_access` and the host's extras (`scopes:`); a refresh or an
  exchange narrows, never widens. The authorization endpoint parks a validated request in the cache
  for ten minutes and sends a browser to the host's `consentUrl?request=`, answers JSON to `Accept:
  application/json` (or always, without a consentUrl); the decision route is the bearer's; a trusted
  client (operator-set or `trustedClients`) or a prior consent needs no screen, `prompt=consent` always
  asks; the authorization response carries `iss` (RFC 9207). Client authentication: secret basic or
  post, `private_key_jwt` (firebase/php-jwt against the client's `jwks` or a cached `jwks_uri`, `aud`
  the endpoint or the issuer, `jti` once), `none` for public clients. DPoP (RFC 9449): proofs verified
  with the server clock (`JWT::$timestamp`), five minutes of freshness, `jti` once in the cache, `htu`
  without query; `dpop: off|optional|required`, a client may demand it (`dpop_bound_access_tokens`).
  Token exchange (RFC 8693) takes a session's access token (core's parser) or one of the provider's,
  issues `act` naming the requesting client (and an actor token's subject), chained. CIBA is poll mode
  only; the host notifies from `oauth.ciba_requested`. DCR (RFC 7591) off by default, never trusted.
  CIMD: an `https` client id is fetched once an hour over the host's PSR-18 client (64 KiB), must name
  itself, is validated as a registration limited to `none` or `private_key_jwt`; loopback, private,
  link-local and mapped addresses and the RFC 6761 names (`localhost`, `.local`, `.internal`,
  `.home.arpa`, `.onion`, `.test`, `.example`, `.invalid`, `.arpa`) are refused; the name is not
  resolved. The well-known documents live under the mount (`<baseUrl>/.well-known/...`, OpenID-conformant
  for a path issuer). Rate groups: the client-facing routes (`/oauth2/token`, `revoke`, `introspect`,
  `device/code`, `authorize`) use `token_refresh` (60 a minute per IP: clients poll and SPAs start
  flows), `ciba` `mfa_send` (it reaches a person), `register` `register`. Organizations manage their
  clients under `org.update` and cannot trust them; operators (`polaris/admin`, `own`) can.
  `polaris/audit` and `polaris/admin` are required. · Rejected: storing access tokens (a `jti` row is
  enough to revoke and introspect); a nonce-based DPoP server challenge (`use_dpop_nonce`, a second
  round trip every client must implement; the five-minute window and the replay cache cover the same
  risk at this scale); `/.well-known` at the host root (the adapters would register a route outside the
  mount for one document; the OpenID form is conformant); a `pollInterval` of 1 second in the fixtures
  (a throttle a replay cannot time; zero turns it off and the throttle is unit-tested with a clock).
- 2026-10-10 · WP3 · Core's test normaliser masks, for the two packages' fixtures: the keys `hint`,
  `client_id`, `client_secret`, `user_code`, `device_code`, `request`, `id_token`, `auth_req_id`; the query
  parameters `request` and `user_code`; and the epoch claims `exp`, `iat`, `nbf`, `auth_time`,
  `updated_at` when integers. The hosts rewrite `Cache-Control` (Laravel answers `no-store, private`), a
  transport header the harnesses already ignore; the tests assert the directive, not the value.
- 2026-10-10 · WP3 · Security review of the two packages and the seams (before the PR), fixed: (1) core's
  session parser (`PolarisTokenParser`) refuses a JWT whose header `typ` is not `JWT` and, when no
  audience is configured, any token naming one: the provider's access tokens (`at+jwt`) and ID tokens
  (`aud` = the client) are signed with core's key and would otherwise have parsed as sessions, with the
  user's full authority, everywhere `tokenFactory()` is used (the admin principals, the host guards,
  multi-session, anonymous, the exchange) — a logged core change that no valid session is affected by;
  (2) a delegated credential (a token carrying `delegated`: an API key, an OAuth access token) may read
  and may do what a permission it holds allows, but core's authorization middleware refuses it on a
  write or destructive route that needs no permission (the self-service ones: enrolling a factor,
  creating an organization, logging out everywhere, deciding a consent or a device, minting or rotating
  a key) and on every `step_up` route — so a stolen key or token cannot turn itself into a wider,
  durable grant, nor add credentials; (3) `Gate::authority()` drops the `superadmin` role from a
  delegated authority (the escalation and cross-organization exemptions do not follow a key or a
  token); (4) the provider's resolver drops `auth_time` (a client never passes a step-up gate as the
  person); (5) CIMD and `jwks_uri` share one validator: https on port 443 only, no credentials in the
  URL, a trailing dot stripped, numeric hosts in any spelling refused, and the fetch error answered
  generically (the reason is not an oracle for internal hosts); the metadata document is cached only
  once it validated; a metadata client may only act for a user (no `client_credentials`, no exchange);
  (6) a redirect URI's custom scheme must be a reverse-domain name (`com.example.app`), never
  `javascript`, `data`, `vbscript`, `file`, `blob` or `about`; (7) the backchannel grant (CIBA) is
  granted by an operator only: it reaches people by their email, so an organization cannot give it to
  itself; (8) an authorization code presented twice revokes the tokens its first redemption issued (the
  family is the code, RFC 9700 §4.5); (9) a DPoP-bound subject token cannot be unbound through an
  exchange (the proof is required and the exchanged token stays bound); (10) introspection is for
  clients that authenticate (RFC 7662 §2.1); (11) the DPoP replay key is the thumbprint and the `jti`
  (a client cannot burn another's), the assertion replay entry is capped at ten minutes, the
  authorization request's parameters are bounded and its id validated before the cache is asked, the
  fetched body is read up to the limit rather than whole; (12) a member who leaves takes the
  organization's keys they act for (`MemberRemoved`), and another admin rotates a creator's key only
  within what they hold themselves. · Kept as residual risks, with the reason: the metadata host name is
  not resolved (a public name that resolves to a private address is the host network's egress policy;
  the PSR-18 client is the host's); the one-use reads on the PSR-16 cache are a get then a set (as sso's
  and the WP2 entry; an atomic `add` where the cache offers one is the upgrade); device user codes are
  stored in clear and have no attempt counter (2.6e10 of space behind the authenticated budget); refresh
  and exchange do not recheck the user's status (the resolver does at every use); a consent is keyed by
  the client id, so a CIMD client inherits its earlier consent after a document change (the host's
  consent page shows the host name); the CIBA `unknown_user_id` answer is the standard's and now needs
  an operator's client; API keys survive a password change or a logout everywhere (revocation is the
  control, as decided); `resource` is accepted verbatim (an `aud` for any URL, as RFC 8707 allows).
  · Rejected: a `delegable: true` opt-in per route (every self-service write would have to be audited
  for it; the effect-based rule needs no annotation and the permissioned routes stay delegable);
  refusing delegated tokens on every permissionless route (`/auth/me`, the reads, are what a key is for);
  a DPoP server nonce (as before).
- 2026-10-10 · WP4 · Spec §9.5: `mcp/sdk` (the official `modelcontextprotocol/php-sdk`, ^0.8, which speaks
  the 2026-07-28 stateless profile and the 2025 handshake from one builder) is a hard `require` of
  `polaris/mcp`, not a `suggest` of its server half. The protect half (`McpProtectedResource`) uses none of
  it, but it sits in front of a PHP MCP server, which is in practice built on the same SDK; a suggested
  dependency would mean `class_exists` branches in the server half and a second CI matrix for one package.
  The SDK's transports stay behind `Polaris\Mcp\Transport\{Stdio,Http}`; Polaris passes its PSR-17
  factories explicitly, so the SDK's `php-http/discovery` Composer plugin is never needed and the root
  `allow-plugins` lists it as `false`. · Rejected: `suggest` plus a runtime check; a separate
  `polaris/mcp-server` package (one more split, Packagist entry and README for one class).
- 2026-10-10 · WP4 · Spec §9.6: a Polaris protocol document with a compatibility subset, not exact
  compatibility. Better Auth's Agent Auth Protocol (agentauthprotocol.com, `1.0-draft`) is a moving
  draft whose host model (host JWTs keyed by a thumbprint, Ed25519 only, `/agent/*` lifecycle routes,
  async and streamed execution) would be a second identity system beside core's OAuth provider.
  `docs/better/agent-auth-compat.md` becomes the normative Polaris document: what Polaris serves, the
  JSON Schema the discovery document validates against, and the subset an AAP agent can rely on without
  a mode switch (Polaris only adds fields): the discovery fields `version`, `provider_name`,
  `description`, `issuer`, `default_location`, `algorithms`, `modes`, `approval_methods`, `endpoints`;
  the capability object (`name`, `description`, `input`, `location`); the agent JWT (`typ: agent+jwt`,
  `sub` = the agent, `aud`, `iat`, `exp`, `jti`, `capabilities`, sent as `Authorization: Bearer`);
  execute `{capability, arguments}` answering `{data}`; the error codes `invalid_jwt`,
  `capability_not_granted`, `constraint_violated` (with `violations`), `capability_not_found` as the
  `error` of Polaris problem documents. Not served: host JWT registration, key rotation routes,
  reactivation, async and streamed execution. · Rejected: exact compatibility (a second agent identity
  model to keep in step with a draft); a compatibility switch (nothing to switch: the shapes are additive).
- 2026-10-10 · WP4 · The agent SDKs (spec §4.7): generated from the manifest are the route table of the
  `agents` and `oauth` routes the SDKs call (method, path, input fields), checked in as
  `packages/agent-ts/src/routes.ts` and `packages/agent/src/Routes.php` and drift-checked in CI, and, for
  TypeScript, the request and response types, imported from `@polaris-auth/client`'s generated
  `schema.d.ts`. Hand-written are only the loops and the cryptography: signing request JWTs and
  `private_key_jwt` assertions (WebCrypto in TypeScript, `firebase/php-jwt` in PHP: no new runtime
  dependency), polling an approval (`interval`, `slow_down`, expiry), the token exchange and client
  credentials calls, and receipt verification (the hash chain and the core-key signature against
  `/auth/.well-known/jwks.json`). Keys are ES256 (P-256) or EdDSA (Ed25519). · Rejected: SDKs wrapping
  the whole client (an agent needs a dozen calls, not the 200 routes); a JOSE library dependency
  (WebCrypto and the JWT library core's packages already use cover it).
- 2026-10-10 · WP4 · An agent is an OAuth client of `polaris/oauth-provider` (§4.3 items 1 and 2 reuse
  0.9.0 as they are): registering or enrolling an agent creates the client through `Clients::create`
  and the agent's id is the client's `client_id`, so a client-credentials token's `sub` is the agent.
  An autonomous agent's client may use `client_credentials`, a delegated agent's the token exchange;
  `auth: private_key_jwt` stores the agent's public JWK as the client's `jwks`, `client_secret` mints a
  `pcs_` secret shown once, `delegated_token` is a public client limited to the exchange (the user's
  subject token is the credential). The client's `scopes` follow the agent's active grants (the
  permissions their capabilities require), so a token can only be minted within what was granted.
  `polaris/oauth-provider` changes twice, both additive: the exchange's `act` names the requesting
  client by `sub` as RFC 8693 §4.1 has it (`{sub, client_id}`, was `{client_id}`; one recorded WP3
  fixture's shape gains the masked `sub`), and `OAuthPlugin(audiences: [...])` lists further audiences
  that name this server (`<baseUrl>/mcp`, the resource MCP clients ask for), accepted by its resolver as
  the issuer is. · Rejected: an agent token endpoint in the agents plugin (a second authorization
  server); recognising agents by a client id prefix (the id is a UUID like every other).
- 2026-10-10 · WP4 · The agent principal: the agents plugin's middleware (after token authentication,
  before step-up and authorization) recognises a token whose `client_id` is an agent's and replaces it
  in-process: the agent must be active (else `401 agents/agent_inactive`); `delegated` becomes the
  token's delegated permissions intersected with the agent's live grants (decision #3, so a grant
  revoked takes effect at the next request, not at the token's expiry); the metadata gains
  `actor_type: agent`, `agent_id` and `act: {sub: <agent>, type: agent}`. A delegated agent's token
  keeps the user as `sub`; an autonomous agent's acts as its owner (a user's agent as the user, an
  organization's as the member who registered it, in that organization), as an organization's API key
  does (WP3), so core's RBAC, the delegation rule and every endpoint see the owner and the agent. Agent
  events are `Auditable` with `actor_type = agent`, the agent as actor and the user as subject.
- 2026-10-10 · WP4 · The agent-facing routes (`POST /agents/execute`, `/agents/grants/request`,
  `GET /agents/session`, `POST /agents/enroll`) are `auth: public` and authenticate the agent themselves,
  as `/oauth2/userinfo` does: core's delegation rule refuses a delegated token on a permissionless write
  route, and these routes are the agent's. Two credentials: the agent's OAuth access token (verified by
  the oauth plugin's resolver), or a signed request JWT (§4.3 item 3): header `typ: agent+jwt`, `alg`
  ES256 or EdDSA, signed by the agent's registered JWK (no `jku`, no `jwk` header), `sub` = the agent,
  `aud` = the exact URL called (scheme, host, path; no query), `iat`, `exp` with `exp - iat` ≤ 300
  seconds, `jti` once (the cache, keyed by agent and `jti`, until `exp`), optional `htm`, `htu` and
  `body_hash` (base64url SHA-256 of the raw body) checked when present, optional `capabilities`. The
  owner-facing routes (register, hosts, list, approvals, decide, suspend, resume, revoke, receipts,
  grant delete) are `auth: bearer` self-service writes, so no delegated credential (a key, an OAuth
  token, an agent) can approve a grant or register an agent; an organization's agents need `org.update`
  in that organization, checked by the endpoint (not `requires_permissions`, which would make the route
  delegable).
- 2026-10-10 · WP4 · Grants and budgets: a grant request names capabilities and asked constraints; the
  approval's method (`device_authorization`, `ciba`, `in_app`) only changes how the owner finds it (a
  user code looked up at `GET /agents/approvals/{code}`, an `agent.grant.requested` event the host turns
  into a push, the list `GET /agents/approvals`); all decide at `POST /agents/approvals/{id}/decide`,
  which checks the strength the capability's risk requires (`session`, `step_up`: core's step-up
  freshness, `passkey`: a recent `passkey` sign-in) and that the owner holds the capability's
  permission. `autoApprove` (default: `low` risk, budget 100 executions) approves without a person when
  the owner holds the permission. Constraints are AAP's operators per argument (`max`, `min`, `in`,
  `not_in`) plus `pattern`, and `budget: {count|amount, window?}`: a counter decremented by a
  conditional update in the execution's transaction; the window, when set, is the grant's lifetime; an
  exhausted grant answers `agents/budget_exhausted` and a refill is a new request.
- 2026-10-10 · WP4 · Receipts: one per execution in the execution's transaction, a chain per agent
  (`seq` unique per agent, `prev_hash`, `hash` = SHA-256 over the canonical JSON of the receipt's fields
  and `prev_hash`), signed by core's key as a compact JWS over the hash (`typ: receipt+jwt`, verifiable
  with `/auth/.well-known/jwks.json`); `GET /agents/receipts/{id}/verify` recomputes the hash, checks the
  signature and the link to the previous receipt. Revoking an agent writes a final `sealed` receipt and
  nothing is chained after it. Inputs are stored as a hash, never in clear.
- 2026-10-10 · WP4 · Capabilities with a `location` (a host route): `AgentRequestMiddleware` is a PSR-15
  middleware the host puts in front of its routes (`AgentsPlugin::of($graph)->requestMiddleware()`); a
  request whose URL is a capability's location is refused unless an agent authenticates for that URL and
  holds a grant whose constraints the arguments (the JSON body) satisfy; the budget, the host handler and
  the receipt (outcome from the response status) run in one transaction, and the handler reads the
  evaluated grant from the request attribute `polaris.agents.grant`. Capabilities without a location
  run the configured `handler` at `POST /agents/execute`. `GET /.well-known/agent-configuration` is a
  route under the mount, as the OAuth documents are; the root alias is the host's.
- 2026-10-10 · WP4 · `polaris/mcp` as an MCP server: one tool per manifest route the principal may call,
  named `polaris.` plus its spec file's path under `api/` with `/` and `-` read as `.`
  (`orgs/members-list.yaml` is `polaris.orgs.members.list`); the input schema is the route's OpenAPI
  operation folded into one object (path, query and body fields, from the input rules), the output
  schema the typed example; annotations from `effect`. Listed per principal: public routes (not
  `mfa_token` ones), bearer routes whose permissions the principal's authority holds and the delegation
  rule allows, admin routes for an operator principal; plugins add tools through
  `Polaris\Mcp\ToolProvider` (the agents plugin: every capability, an execution with its receipt). A
  call is dispatched through `Polaris\Psr15\Pipeline` as an in-process request, so it answers exactly
  what the route answers (`structuredContent: {status, body}`, `isError` from 4xx/5xx); the principal
  travels as a request attribute that the mcp plugin's bearer resolver returns, never as a header, so a
  DPoP-bound token proven once at `/mcp` serves every inner call and nothing on the wire can set it.
  `POST /mcp` is a public route whose endpoint applies `McpProtectedResource` (core's keys, `aud` = the
  `/mcp` URL or the issuer) and then resolves the principal through the bearer resolvers;
  `bin/polaris mcp` (stdio) takes its credential from `POLARIS_MCP_TOKEN` and adds the read-only CLI
  commands (`schema:export`, `schema:diff`, `manifest`, `doctor`) as tools. Resources:
  `polaris://manifest` (the OpenAPI document), `polaris://schema` (the schema export),
  `polaris://problems/<plugin>/<name>`. `legacy: reject` by default (spec §3.7: the 2026-07-28 profile);
  `allow` serves the 2025 handshake with sessions in the PSR-16 cache. The protected resource keeps its
  own small DPoP proof check (`polaris/mcp` does not require `polaris/oauth-provider`). · Rejected:
  re-sending the bearer on inner calls (a DPoP proof is bound to `/mcp`'s URL); a tool per HTTP method
  and path (the spec names tools by route).
- 2026-10-10 · WP4 · `polaris/mcp` as built: the SDK's builder is assembled per principal (per HTTP
  request; once per stdio process) with explicit tools and handlers, so the SDK lists them, validates
  the arguments against the input schema and runs them (no custom `tools/list`/`tools/call` handlers).
  Over HTTP, `/mcp` accepts only JWTs whose `aud` is `<baseUrl>/mcp` or the issuer (OAuth access
  tokens); a session token or an API key is `invalid_token` there and is a stdio credential
  (`--token`, `POLARIS_MCP_TOKEN`). The SDK's stdio transport speaks the 2025 handshake (every stdio
  client sends `initialize`); HTTP serves 2026-07-28 by default and the handshake with `legacy: allow`
  (sessions in the PSR-16 cache under `polaris.mcp.session.`). The SDK's own HTTP middleware (CORS, DNS
  rebinding: localhost only) is off: the host owns those. Admin-tagged routes are listed for an operator
  (admin's `Principals`, when the admin plugin is registered) and only for them the inner request carries
  the credential as `Authorization: Bearer`, because the admin middleware authenticates from the header
  and its principals are never DPoP-bound; every other inner call carries the attribute only. CLI tools
  run through a fresh `Polaris\Cli\Application` (no bootstrap, so no recursion), answering
  `{status: 200|500, body: <output>}`. `polaris://problems/{plugin}/{name}` answers what the manifest
  declares for that code. The protected-resource metadata of Polaris's own `/mcp` advertises the required
  scopes and the permission catalog. The functional fixture freezes the whole `tools/list` of core,
  audit, admin and oauth, so a changed summary or field there re-records it (the contract freeze working).
- 2026-10-10 · WP4 · `polaris/agents` as built: 23 routes (the owner's `auth: bearer` routes, the agent's
  public self-authenticated ones, `/admin/agents` list and revoke for operators). The device page's data
  is `GET /agents/approvals/code?user_code=` rather than `/agents/approvals/{code}`: the fixtures mask
  only UUIDs in paths (oauth's device verify takes `?user_code=` for the same reason). `/agents/enroll`
  uses the `token_refresh` group (a host enrols many agents; `register` is five an hour per IP, shared
  with `/auth/register`), `/agents/register` `register`, decide `mfa_confirm`. OAuth reads an empty
  client scope list as "any scope", so an agent without a live grant keeps the harmless `profile` scope
  and can mint only a token for its own routes. The stored JWK carries `alg` and `kid` (the agent's, or
  its RFC 7638 thumbprint), which the SDKs sign with. Receipt signatures have no `exp` (a receipt stays
  verifiable) and are checked through the oauth plugin's `Jwt::verify`, so a key rotation keeps them
  valid; `verify` compares the signature and the successor's link against the recomputed hash, so a
  receipt edited in the database fails its own check and the next one's. Capabilities asked at
  registration or enrolment go through the same policy; what is not auto-approved waits as an `in_app`
  approval. An absent constrained argument is a violation; budgets are integers (amounts round up); a
  grant is `exhausted` when its remainder reaches zero, a call it cannot cover answers
  `budget_exhausted` without changing it. A handler that throws rolls the execution back and leaves no
  receipt. The kill switch emits one `agent.revoked` (with the number of grants ended) and
  `agent.receipt.sealed`; a member who leaves takes the organization's agents they registered with them
  (revoked and sealed, by `system`); an erased user or organization erases its agents, their clients and
  tokens, grants, approvals, receipts and hosts. MCP: a tool per capability with a handler (location
  capabilities run at the host), `destructive` for `risk: high`. Problem types beyond the protocol
  document's table: `agents/unauthorized`, `invalid_arguments` (422), `invalid_input`, `not_found`,
  `forbidden`, `conflict`, `step_up_required`, `permission_not_held`, `sealed`. `polaris/oauth-provider`
  gains `Tokens::revokeForClient()`; disabling the client and syncing its scopes use `Clients::update`.
- 2026-10-10 · WP4 · The agent SDKs as built (refining the SDK entry above): `@polaris-auth/agent` does not
  depend on `@polaris-auth/client`; its generator reads `packages/client-ts/openapi.json` and emits
  `src/routes.ts` and a `schema.d.ts` filtered to the routes it calls, so it has no runtime dependency
  (fetch and WebCrypto only, Node and edge); the logic's own shapes (grant, approval, receipt, session)
  are typed by hand because example-derived types read an absent field as `null`. `polaris/agent` takes
  any PSR-18 client and ships a small stream-wrapper client so it works with none installed; its
  `Routes.php` is generated by `packages/agent/bin/generate-routes`; both are drift-checked in the new
  `agent-ts` CI job, which also runs the TypeScript SDK's enrol-to-receipt run against the Slim demo.
  The approval poller polls `GET /agents/session` (the agent's one view of its grants), matches grants by
  `approval_id`, adds five seconds on `slow_down` or a 429, and stops at the approval's expiry, after
  `maxAttempts`, or on an abort. Every request JWT binds `htm`, `htu` and, with a body, `body_hash` over
  the bytes sent; the lifetime defaults to 60 seconds (capped at 300). Receipts verify locally (the
  PHP-identical canonical JSON, the `receipt+jwt` signature against the server's JWKS by `kid`, the link
  to a previous receipt when given). The Slim demo registers `oauth` (with `audiences: [<base>/mcp]`),
  `mcp` and `agents` (one capability `demo.echo`, low risk, auto-approved) and gains `approve.html`, the
  reference agent approval page; `walkthrough.sh` gains, when `/.well-known/agent-configuration` answers,
  an MCP `tools/list` with a token exchanged for the `/mcp` resource (curl only) and the agent steps
  through `examples/slim/bin/agent-walkthrough.php` on `polaris/agent` (no second Node project). The first
  npm publish of `@polaris-auth/agent` is manual at the release (trusted publishing binds to an existing
  package).
- 2026-10-12 · WP4 · Security review of `polaris/mcp`, `polaris/agents` and the oauth-provider changes
  (before the PR), fixed: (1) a confused deputy: the token exchange is open to any session, so anyone
  could exchange their own session for a token naming another user's delegated agent's client and
  execute that agent's grants for its owner; a token naming an agent's client must now have the agent
  (client credentials) or the agent's subject (the owner; for an organization's agent, the member who
  registered it) as its `sub`, else `401 agents/invalid_jwt` on every route, `/agents/*` and MCP alike;
  (2) an agent's OAuth client was created in the registering member's organization, so the
  organization's self-service client routes could rewrite its credentials and grant types (and mint
  tokens acting as the owner) or delete it past the kill switch: agents' clients now belong to no
  organization (the agent row carries it; the plugin manages and erases the client); (3)
  `AgentRequestMiddleware` was fail-open on spellings of a `location` (`/invite/`, `//invite`,
  `/./invite`, `/%69nvite`, `http` behind a proxy): locations and request URLs are compared normalised
  (RFC 3986 §6.2.2, scheme ignored for the match so a proxy's `http` is guarded and then fails the `aud`
  check), and `requestMiddleware($graph, 'capability')` binds the middleware to a route's capability so
  every request through it is checked; (4) the policy's auto-approval budget is a ceiling: an asked budget
  of another kind, larger or with a longer window waits for a person; (5) the MCP protected resource
  refetches a remote JWKS for an unknown `kid` at most once a minute; (6) a pending grant for the same
  capability is reused, at most five approvals are pending per agent (`409 agents/conflict`), an approval
  past its lifetime reads `expired`; (7) a decision parses the constraints first and runs in one
  transaction; (8) a member who leaves takes the organization's hosts they created with them; (9) an
  execution locks the agent row first (a concurrent suspend or revoke refuses it rather than racing the
  seal) and a receipt sequence collision answers `409 agents/conflict`. With the fixes, the agents
  plugin's `error` member follows every plugin's rule (`agents_not_found`) except for the codes the
  protocol document defines, which stay bare, and its `401`s answer RFC 6750's `WWW-Authenticate`
  (`Bearer`, or `Bearer error="invalid_token"`). · Kept as residual risks, with the reason: the replay
  stores (request-JWT `jti`, the MCP DPoP proofs) are a PSR-16 get then set, as WP2's and WP3's (an
  atomic `add` is the upgrade); approval user codes (19^8) are stored in clear without an attempt counter,
  looked up by a signed-in owner behind core's authenticated budget; the `step_up` strength passes for a
  user without a confirmed factor, exactly core's step-up rule; `aud` is compared with the URL the host
  builds (a wrong proxy configuration makes valid JWTs fail, never pass); `pattern` constraints run under
  PCRE's limits on the agent's own request; `agents/invalid_jwt` tells an unknown agent from a bad
  signature (agent ids are UUIDs and no secret); the `/mcp` tool list under-reports for an autonomous
  agent's token (every call still runs through the pipeline); receipt signatures have no `exp` by design;
  the middleware reads and rewinds the body (a non-seekable host stream is a robustness limit); the token
  endpoint still mints an exchanged token naming another user's agent (dead on every route; refusing it
  there needs an oauth seam for one caller); an operator may delete an agent's client through
  `/admin/oauth/clients` (operators are trusted; routing it through the kill switch is a follow-up).
- 2026-10-12 · WP4 · The Slim demo runs under PHP's built-in server with `public/index.php` as its router
  (`php -S 127.0.0.1:8080 -t public public/index.php`; the front controller hands real files back to the
  server): PHP 8.3's built-in server answers its own 404 for any path under a dot directory
  (`/.well-known/agent-configuration`, and core's `/auth/.well-known/jwks.json`) instead of running
  `index.php`, which 8.5 does, so CI (8.3) skipped the agent steps while local runs (8.5) passed. The shared
  walkthrough starts the server with `POLARIS_ROUTER` when a demo sets it, and the Slim demo sets
  `POLARIS_AGENTS=required` so the agent and MCP steps fail rather than skip when the plugin does not
  answer; the other demos are unchanged.
