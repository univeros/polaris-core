# polaris/sentinel

Sentinel for [Polaris for PHP](https://github.com/univeros/polaris-core): a local risk engine on sign-up,
sign-in, password reset and code sends. Signals score an attempt (velocity, credential stuffing, IP rules,
devices, disposable domains and, with a provider, captcha, impossible travel and breached passwords); a
policy allows, challenges or blocks; `observe` mode records without enforcing, so an instance tunes on its
own audit trail before it enforces. Every decision where a signal spoke is a row for the operators and a
`sentinel.evaluated` event.

```sh
composer require polaris/sentinel
```

```php
use Polaris\Admin\AdminPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Sentinel\SentinelPlugin;

$polaris = Polaris::create(new Config(..., plugins: [new AuditPlugin(), new AdminPlugin(), new SentinelPlugin()]));
```

`polaris/audit` and `polaris/admin` are required and must be registered too: the decisions are
`sentinel.*` events in the audit store, and the operator routes use the admin plugin's principals. In
Laravel, Symfony and Yii the three instances go in the adapter's `plugins` configuration; the three tables
(`polaris_sentinel_decision`, `polaris_sentinel_ip_rule`, `polaris_sentinel_device`) join `polaris:install`,
`schema:create` and `schema:diff`, the routes join the route table.

## What is judged

The plugin's PSR-15 middleware runs on the guarded routes before the endpoint, with what the request
carries: the email, the client address and user agent, the `polaris_device` cookie (set by the middleware
on the first response when absent, one year, `HttpOnly`, `SameSite=Lax`), a `captcha_token` and, for the
breach lookup, the password (never stored).

| Route | Attempt |
| --- | --- |
| `POST /auth/register` | `sign_up` |
| `POST /auth/login` | `sign_in` |
| `POST /auth/password/forgot` | `password_reset` |
| `POST /auth/email/verify/resend` | `verification_send` |
| `POST /auth/mfa/challenge` | `otp_send` |

The outcomes the engine cannot see at attempt time come from core's events: a failed sign-in feeds the
credential-stuffing ratio; a sign-in records the device of the request, its address and, with a geo
resolver, its location. Core's routes and responses are unchanged: the sentinel only adds two problem
documents in front of them.

## Signals and the policy

| Signal | Fires when | Score | Provider |
| --- | --- | --- | --- |
| `ip_list` | the address matches an operator's rule | block 100, allow −100 (clears the attempt) | `polaris_sentinel_ip_rule` |
| `velocity` | attempts per address, email or device exceed a limit in a window (20, 10, 30 per 10 min by default) | 50 per dimension | `CounterStore` (PSR-16 by default) |
| `credential_stuffing` | one address tried 5 distinct accounts, or failed 80 % of at least 10 sign-ins, in 10 min | 60 each | `CounterStore` |
| `disposable_email` | a sign-up with a domain on the list | 60 | `DomainList` (the bundled list, CC0, plus yours) |
| `device` | a sign-in from a device the user never used, once they have one | 40 | the device cookie |
| `bot` | a `captcha_token` is present: invalid, a bot's guess; valid, a passed challenge | 80 / 0 | `BotVerifier` (Turnstile, hCaptcha) |
| `impossible_travel` | the distance from the last sign-in's location over the time elapsed exceeds 900 km/h | 70 | `GeoResolver` (MaxMind DB) |
| `breached_password` | a new password appears in a breach corpus | 50 | `BreachChecker` (HIBP k-anonymity) |

The policy sums the scores (capped at 100): below 40 allow, from 40 challenge, from 80 block
(`new Policy(challengeAt: 40, blockAt: 80)`). A verified captcha token turns a challenge into an allow;
a block stays a block. Silence is not recorded; a decision where a signal spoke is stored with its
signals and reasons and emitted as `sentinel.evaluated` (the email hashed, never the password or token).

A signal that throws is skipped and logged: the engine fails open. Your own signals implement
`Polaris\Sentinel\Signal` (and `Resettable` when an operator's unblock should clear them) and go in
`signals:`; `builtIn: false` runs yours alone.

## Modes and answers

- `mode: 'observe'` (the default): every attempt goes through; the decisions say what would have happened.
- `mode: 'enforce'`: a block answers `403 sentinel/blocked` with a generic detail (the reason stays in
  the record and the audit event); a challenge answers `403 sentinel/challenge_required` with
  `challenge: captcha` when a `BotVerifier` is configured, and the client retries the same request with
  the `captcha_token` it obtained. Without a verifier nothing can answer a challenge, so the challenge
  band is recorded and let through; configure one before enforcing, or raise `challengeAt`.

Both are RFC 9457 problem documents (`application/problem+json`) that also carry core's `error` and
`message`, as every plugin route's errors do.

## Configuration

```php
new SentinelPlugin(
    mode: SentinelPlugin::ENFORCE,
    policy: new Policy(challengeAt: 40, blockAt: 80),
    velocity: ['ip' => [20, 600], 'email' => [10, 600], 'device' => [30, 600]],   // limit, window seconds
    verifier: new TurnstileVerifier($httpClient, $requestFactory, $streamFactory, $secret),  // or HcaptchaVerifier
    geo: new MaxMindGeoResolver('/var/lib/GeoLite2-City.mmdb'),                   // needs maxmind-db/reader
    breachChecker: new HibpBreachChecker($httpClient, $requestFactory),
    disposableDomains: ['trash.example'],                                          // beside the bundled list
    disposableListFile: '/var/lib/polaris/disposable-domains.txt',                 // instead of the bundled file
    counters: new CacheCounterStore($redisCache, $clock),                          // any PSR-16 store; the graph's cache by default
    responses: $responseFactory,                                                   // PSR-17; discovered when omitted
    routes: [...SentinelMiddleware::ROUTES, '/auth/password/reset' => Attempt::PASSWORD_RESET],
    signals: [new MySignal()],
);
```

Every provider is an interface (`BotVerifier`, `DomainList`, `GeoResolver`, `BreachChecker`,
`CounterStore`), so a host swaps an implementation without touching anything else. The HTTP providers
take a PSR-18 client and PSR-17 factories; a transport failure is a failed captcha and a "not breached"
password. When a `breachChecker` is configured it also serves core's password-policy port
(`auth.password.breach_check`) unless the configuration sets its own.

`polaris/messaging` takes the sentinel's quiet mode when it is registered: a recipient the sentinel
challenged or blocked in the last hour gets no non-essential message.

## Operators

All under `/admin/sentinel`, for the admin plugin's principals (an admin user's token or an API key);
errors are the admin problems (`admin/unauthorized`, `admin/forbidden`, `admin/invalid_input`,
`admin/not_found`).

| Route | Needs | Does |
| --- | --- | --- |
| `GET /admin/sentinel/decisions?email=&ip=&action=&cursor=&limit=` | read | the decisions, newest first, with signals and reasons |
| `GET /admin/sentinel/ip-rules` | read | the rules in the order they match |
| `POST /admin/sentinel/ip-rules` `{cidr, action, note?}` | own | an `allow` or `block` rule for an address or a CIDR block (both families); `sentinel.ip_rule_created` |
| `DELETE /admin/sentinel/ip-rules/{id}` | own | `sentinel.ip_rule_deleted` |
| `POST /admin/sentinel/unblock` `{identifier}` | support | forgets what the velocity and stuffing signals counted for an email or an address; `sentinel.unblocked` |

The rules are instance-wide, so the routes need the instance scope. The TypeScript client has them as
`client.sentinel.listDecisions()`, `listIpRules()`, `createIpRule()`, `deleteIpRule()` and `unblock()`.

`polaris sentinel:lists --url=<list> [--to=<file>]` refreshes the disposable-domain list from a URL the
host chooses (one domain per line, `#` comments); without a URL nothing is fetched, the bundled list
(`resources/disposable-domains.txt`, refreshed per release) stands. The command needs the plugin's
`httpClient` and `requestFactory` and a `--bootstrap` (or `POLARIS_BOOTSTRAP`) naming the application,
as the other Polaris commands.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
