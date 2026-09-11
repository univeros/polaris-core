# polaris/audit

Audit for [Polaris for PHP](https://github.com/univeros/polaris-core): every Polaris event becomes a
catalogued, redacted, append-only record you can query per user and per organization, stream to your own
sinks and to each organization's drains, prune by policy, and, when you need tamper evidence, chain by hash.

```sh
composer require polaris/audit
```

```php
use Polaris\Audit\AuditPlugin;

$polaris = Polaris::create(new Config(
    ...,
    plugins: [new AuditPlugin(
        retention: ['default' => 'P90D', 'names' => ['user.deleted' => 'P7Y']],
        hashChain: false,                       // true links each row to the previous by SHA-256
        sinks: [new FileSink('var/audit.jsonl')], // beside the database: Psr3Sink, FileSink, WebhookSink, yours
        names: ['billing.invoice_paid' => 'An invoice was paid'],   // your own event names
        httpClient: $psr18, requestFactory: $psr17, streamFactory: $psr17,   // enables the organizations' drains
    )],
));
```

In Laravel, Symfony and Yii the same instance goes in the adapter's `plugins` configuration; the tables
join `polaris:install`, `polaris:schema:create` and `schema:diff`, the routes join the route table.

## What is recorded

`Polaris\Audit\Catalog` is the closed list of names: `user.signed_up`, `session.signed_in`,
`session.sign_in_failed`, `password.changed`, `mfa.enabled`, `mfa.challenge_failed`, `org.member_invited`
and the rest of core's 35 events, each mapped to an actor, a subject, an organization, a session, an IP,
a user agent and a small data map. `Redactor` strips any key matching `password|secret|token|code|otp|
private_key|credential` at any depth and any value wrapped in `Sensitive`, before persistence. A package
registers its own names through the plugin's `names` and emits with `Recorder::record()` or by dispatching
an event implementing `Auditable`; an unknown name is rejected.

Table `polaris_audit_event` (UUID v7 ids, so ordering by id is ordering by time), indexed by name,
time, actor, subject and organization; `polaris_audit_drain`; `polaris_audit_activity`
(`last_active_at` per user, written at most once per `activityInterval` seconds from the sign-in,
refresh, MFA and organization-switch events).

## Routes

| Route | Who | Returns |
| --- | --- | --- |
| `GET /audit/me` | any session | the events where the caller is the actor or the subject |
| `GET /audit/organization/{id}` | a member with `audit.read`, on the active organization | the organization's events |
| `GET /audit/types` | any session | the catalog |

Filters: `names` (comma-separated), `from`, `to` (ISO-8601), `cursor` (the `next_cursor` of the previous
page), `limit` (50 by default, 200 at most). Newest first. Errors are RFC 9457 problem documents
(`audit/forbidden`, `audit/invalid_query`) that also carry core's `error` and `message`.

## Sinks and drains

Sinks are static and configured on the plugin: `DatabaseSink` (always), `Psr3Sink`, `FileSink` (JSON lines),
`WebhookSink` (HTTP POST through a PSR-18 client, HMAC-SHA256 in `X-Polaris-Signature`, a delivery id in
`X-Polaris-Delivery`, retried on transport failures, 429 and 5xx). Every sink is fail-open: a failing sink
is logged and never breaks the operation. Drains are the same delivery per organization, stored in
`polaris_audit_drain` with an encrypted secret and a name filter (`org.*`, `session.signed_in`), managed
through `Polaris\Audit\Drain\Drains` (the admin routes of `polaris/admin`), delivered when the plugin
has a PSR-18 client. Delivery is synchronous, after the operation committed.

## Retention and the hash chain

`polaris audit:prune` (`--bootstrap=<file>` or `POLARIS_BOOTSTRAP` names the application; the adapters'
consoles register the command) deletes what the policy no longer keeps. With `hashChain: true` each row
carries `prev_hash` and `hash` (SHA-256 over the row's canonical JSON and the previous hash, written in
one transaction), pruning ends with an `audit.pruned` checkpoint carrying the hash of the newest pruned
row, and `polaris audit:verify` walks the chain and reports every altered or out-of-sequence row.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
