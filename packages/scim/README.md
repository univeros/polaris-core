# polaris/scim

SCIM for [Polaris for PHP](https://github.com/univeros/polaris-core): a SCIM 2.0 server (RFC 7643, 7644)
per organization. A directory (Okta, Entra ID, Google, JumpCloud, ...) provisions the organization's
members and roles with a connection token the organization creates and rotates itself; the operators see
every connection. Users are members, Groups are roles; deprovisioned users are deactivated, never
hard-deleted unless the connection says so.

```sh
composer require polaris/scim
```

```php
use Polaris\Admin\AdminPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Scim\ScimPlugin;
use Polaris\Sso\SsoPlugin;

$polaris = Polaris::create(new Config(..., plugins: [
    new AuditPlugin(),
    new AdminPlugin(),
    new SsoPlugin(baseUrl: 'https://app.example.com/auth'),
    new ScimPlugin(baseUrl: 'https://app.example.com/auth'),
]));
```

`polaris/audit`, `polaris/admin` and `polaris/sso` are required and must be registered too: every request
is a `scim.*` event in the audit store, the operator routes use the admin plugin's principals, a
connection may be paired with an SSO provider. `baseUrl` is where Polaris is mounted, prefix included:
every resource's `meta.location` derives from it. In Laravel, Symfony and Yii the instances go in the
adapter's `plugins` configuration; the three tables (`polaris_scim_connection`, `polaris_scim_resource`,
`polaris_scim_membership_provenance`) join `polaris:install`, `schema:create` and `schema:diff`, the routes
join the route table. A Yii host adds `application/scim+json` to its request body parser
(`RequestBodyParser::withParser('application/scim+json', JsonParser::class)`); Laravel and Symfony parse
`+json` bodies as JSON already.

## Connecting a directory

1. An organization admin calls `POST /orgs/{id}/scim/connections {name, deprovision?, sso_provider_id?}`
   and gets the connection's `token` (`pst_` and 256 random bits, stored as a keyed hash, shown once) and
   `scim_base_url` (`<baseUrl>/scim/v2/{connectionId}`).
2. The directory is configured with that base URL and `Authorization: Bearer <token>`.
3. It provisions through the SCIM routes below. `GET /orgs/{id}/scim/connections/{connectionId}` shows
   the sync state (users and groups it manages, members it provisioned, the last request);
   `POST .../rotate` answers a new token (the previous one stops at once); `DELETE` decommissions the
   connection (the token stops, the provisioned users stay).

`deprovision` is `deactivate` (the default: a deleted or `active: false` user is banned, every session
ends, and the membership the connection created is removed) or `delete` (the account is anonymised).

## The SCIM server

All under `/scim/v2/{connectionId}`, with the connection token as bearer (a wrong, rotated or
decommissioned token, or another connection's, is a SCIM 401). Documents are `application/scim+json`;
errors are SCIM error documents (`schemas`, `status`, `detail`, `scimType`) that also carry `error` and
`message`.

| Route | Does |
| --- | --- |
| `GET /ServiceProviderConfig`, `/Schemas`, `/ResourceTypes` | what this server supports: filtering, PATCH, bearer tokens; no bulk, sorting or ETags |
| `GET /Users?filter=&startIndex=&count=` | the organization's members; `filter` takes `attr eq\|co\|sw "value"` joined by `and` on `userName`, `emails`, `externalId`, `displayName` (else `invalidFilter`); `startIndex` is 1-based, `count` at most 200 |
| `POST /Users` | a member: created with `userName` as the email, verified, without a password (or found by email when the account exists), joined with the `member` role; `active: false` deactivates |
| `GET\|PUT\|PATCH\|DELETE /Users/{id}` | read; replace the mapped attributes; PatchOp on `active`, `userName`, `displayName`, `name.*`, `externalId`; deprovision (204) |
| `GET /Groups?filter=` | the organization's roles: `displayName` the role name, `members` the memberships holding it |
| `POST /Groups` | a custom role (an empty permission set until an organization admin fills it) with its members |
| `GET\|PUT\|PATCH\|DELETE /Groups/{id}` | read; replace the name and members; PatchOp on `displayName`, `externalId`, `members` (`add`, `replace`, `remove` with a value list or `members[value eq "id"]`); delete (204). The built-in `owner`, `admin` and `member` roles take members but are neither renamed nor deleted |

A SCIM User is a Polaris user with a membership in the connection's organization: `userName` and the
primary email are the email, `displayName`/`name.formatted` the display name, `active` the account
status, `externalId` the directory's own id, `groups` the roles. `id` is the Polaris user id, so the
same person keeps one id across connections and organizations.

Provenance: the connection removes only the memberships it created; a member who predates the
connection is deactivated on deprovisioning but keeps their membership, and a decommissioned connection
leaves everyone in place.

## Operators

`GET /admin/scim/connections?organization_id=&cursor=&limit=` (read; an organization-scoped operator
sees their organization's) and `DELETE /admin/scim/connections/{id}` (own: the connection, its external
ids and provenance removed; the users stay), for `polaris/admin`'s principals. The TypeScript client has
every route as `client.scim.*`.

## Audit

`scim.connection_created|rotated|decommissioned` (actor the user, or the operator), `scim.user_created|
updated|deactivated|reactivated|deleted`, `scim.group_created|updated|deleted` and `scim.request_rejected`
(with the reason) with the connection as the actor (`api_key`).

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
