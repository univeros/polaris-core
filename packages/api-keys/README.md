# polaris/api-keys

API keys for [Polaris for PHP](https://github.com/univeros/polaris-core): keys owned by users and by
organizations, each with a subset of its owner's permissions, an optional rate limit of its own, an
expiry, rotation with a grace window and revocation. Presented as `Authorization: Bearer pk_...` or in an
`x-api-key` header, a key authenticates every Polaris route, core's and the plugins', as its owner with
the delegated permissions, so core's authorization applies to it as to a session. These are the
end-user and organization keys of the Better Auth API Key plugin; the operator keys (`pak_`) belong to
[`polaris/admin`](../admin/README.md).

```sh
composer require polaris/api-keys
```

```php
use Polaris\ApiKeys\ApiKeysPlugin;
use Polaris\Audit\AuditPlugin;

$polaris = Polaris::create(new Config(..., plugins: [
    new AuditPlugin(),
    new ApiKeysPlugin(environment: 'live', rotationGrace: 86400, maxPerOwner: 50),
]));
```

`polaris/audit` is required and must be registered too: every creation, change, rotation and revocation
is an `api_keys.*` event in the audit store. In Laravel, Symfony and Yii the instance goes in the
adapter's `plugins` configuration; the table (`polaris_api_key`) joins `polaris:install`, `schema:create`
and `schema:diff`, the routes join the route table.

## A key as a principal

The plugin registers a bearer resolver (core's seam, `Polaris\Contract\BearerResolver`): on every route
that needs a bearer, core asks it before parsing the JWT. A `pk_` secret is looked up by its keyed hash
and, when the key is live, the request authenticates as the key's subject (its owner, or the member
who created an organization's key) in the key's organization, with `amr: ["api_key"]`, and with the
key's permissions as its *delegated* authority: the authorization middleware resolves the owner's
permissions from the database as always and intersects them with the key's. A key therefore never does
more than its owner may at the time of the call, and loses what the owner loses.

```sh
curl https://app.example.com/auth/orgs/018f.../members -H 'Authorization: Bearer pk_live_...'
curl https://app.example.com/auth/audit/me -H 'x-api-key: pk_live_...'
```

What a key cannot do: a route gated by step-up (removing a factor, deleting an organization,
regenerating recovery codes, registering a passkey) answers `403 api-keys/not_allowed`, because a key
cannot re-authenticate and a stolen key must not add credentials. A key has no session either: nothing
to refresh, log out or switch.

A key is refused (`401 unauthorized`, core's envelope) when it is unknown, revoked, expired, past its
rotation grace, or when its subject is disabled or gone. A revoked or expired key is not an error the
caller can distinguish from an unknown one.

## Routes

All under the caller's bearer (a session, or a key). `organization_id` turns a request into one about
an organization's keys: it must be the caller's active organization, and they need `org.update` in it.

| Route | What |
| --- | --- |
| `GET /api-keys` | The caller's keys, or an organization's (`?organization_id=`): never the secrets, only the last four characters (`hint`). |
| `POST /api-keys` | A key: `name`, `permissions` (a subset of the caller's in their active organization, each from the permission catalog), `organization_id`, `environment` (`live` or `test`, the prefix), `rate_limit` (`{window, max}`), `expires_at`, `metadata`. The secret is in this response only. |
| `GET /api-keys/{id}` | One key. |
| `PATCH /api-keys/{id}` | Name, permissions (still bounded), rate limit, expiry, metadata; `null` clears the limit or the expiry. |
| `DELETE /api-keys/{id}` | Revokes it: it stops at once. |
| `POST /api-keys/{id}/rotate` | A successor with a new secret and the same settings; the old key answers until `rotationGrace` ends, then stops. |
| `POST /api-keys/verify` | For an application that proxies and checks keys itself: `{valid, id, owner_type, owner_id, organization_id, subject, permissions, rate_limit, metadata, status, expires_at}`, or `{valid: false}`. |

Problem types: `api-keys/not_found`, `api-keys/forbidden`, `api-keys/permission_not_held`,
`api-keys/too_many`, `api-keys/invalid_input`, `api-keys/not_allowed`.

## Rate limits and budgets

Core's per-user budget (600 a minute by default) applies to a key as to its owner. A key with its own
`rate_limit` is also counted on its own: `{window: 60, max: 100}` allows a hundred calls a minute for
that key, answered with the `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset`
headers core uses, and `429` with `Retry-After` when spent. An owner holds at most `maxPerOwner` live
keys.

## Configuration

| Option | Default | What |
| --- | --- | --- |
| `environment` | `live` | The prefix of keys created without one: `pk_live_` or `pk_test_`. A key may ask for the other. |
| `rotationGrace` | `86400` | Seconds a rotated key's predecessor keeps answering. |
| `maxPerOwner` | `50` | Live keys a user or an organization may hold. |
| `responses` | discovered | The PSR-17 response factory the middleware answers its `403` and `429` with; the host's `Config::$responseFactory` or an installed implementation otherwise. |

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
