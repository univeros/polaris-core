# polaris/admin

Admin for [Polaris for PHP](https://github.com/univeros/polaris-core): the operator API over users, sessions,
MFA, organizations, audit drains and statistics, for admin users and API keys, every action audited. API-only:
a dashboard, a support tool or an integration talks to `/admin/*`; hosts add nothing beyond the plugin.

```sh
composer require polaris/admin
```

```php
use Polaris\Admin\AdminPlugin;
use Polaris\Audit\AuditPlugin;

$polaris = Polaris::create(new Config(..., plugins: [new AuditPlugin(), new AdminPlugin()]));
```

`polaris/audit` is required and must be registered too: every admin action is an `admin.*` event in its
store, and the statistics come from its tables. In Laravel, Symfony and Yii both instances go in the
adapter's `plugins` configuration; the two tables (`polaris_admin_grant`, `polaris_admin_key`) join
`polaris:install`, `schema:create` and `schema:diff`, the routes join the route table.

## Principals

Three kinds of caller reach the admin routes, resolved by the plugin's middleware from the `Authorization`
header; the routes are declared `auth: public` so core's bearer middleware leaves API keys alone.

- **A superadmin**: a user holding core's global `superadmin` role is an `owner` on the instance, with no grant.
- **An admin user**: a Polaris user with a grant in `polaris_admin_grant` (one per user; a new grant replaces
  it): a role, a scope (`instance` or one organization id), an optional expiry. Created with
  `polaris admin:grant <email> <role>` or `POST /admin/grants`. The user calls the routes with their usual
  access token.
- **An API key**: `polaris_admin_key`, a role, a scope, an optional IP allowlist (addresses or CIDR blocks) and
  expiry; `pak_` and 256 random bits, stored as a keyed hash, shown once. Created with
  `polaris admin:key <name> <role>` or `POST /admin/keys` (owners). Sent as `Authorization: Bearer pak_...`.

An impersonation token (below) never reaches the admin routes (`403 admin/impersonation_denied`); a disabled
user is no operator; a lapsed grant or key is refused (`401 admin/unauthorized`).

The role matrix, deny by default, each role including the ones below it:

| capability | viewer | support | admin | owner |
| --- | --- | --- | --- | --- |
| read users, sessions, MFA factors, organizations, audit, stats | ✓ | ✓ | ✓ | ✓ |
| revoke sessions | | ✓ | ✓ | ✓ |
| ban and unban, set a password, remove or reset MFA, set member roles, delete users and organizations | | | ✓ | ✓ |
| impersonate | | | ✓ | ✓ |
| manage grants, API keys and audit drains | | | | ✓ |

An organization-scoped principal (a grant or key whose scope is an organization id) may call the
organization routes for that organization only (read it, its drains, its audit trail; delete it, set its
members' roles; create keys and grants scoped to it); the user, key, grant and stats routes need the
instance scope (`403 admin/forbidden`).

## Routes

All under `/admin`. Errors are RFC 9457 problem documents (`admin/unauthorized`, `admin/forbidden`,
`admin/impersonation_denied`, `admin/not_found`, `admin/conflict`, `admin/invalid_input`) that also carry
core's `error` and `message`. Lists are oldest first (ids are UUID v7) and cursor-paginated (`cursor` is the
`next_cursor` of the previous page; `limit` 50 by default, 200 at most).

| Route | Needs | Does |
| --- | --- | --- |
| `GET /admin/users?email=&status=&cursor=&limit=` | read | the users (exact email, status active/disabled/locked) |
| `GET /admin/users/{id}` | read | one user with `last_active_at` from the audit plugin |
| `POST /admin/users/{id}/ban`, `/unban` | manage | core's disable (every session ends) and enable (lockout cleared) |
| `POST /admin/users/{id}/password` `{password}` | manage | a new password under the policy; every session ends |
| `DELETE /admin/users/{id}` | manage | core's anonymisation (tombstone row, factors and challenges scrubbed) |
| `POST /admin/users/{id}/impersonate` | impersonate | an access token acting as the user (below) |
| `GET /admin/users/{id}/sessions` | read | the active sessions |
| `DELETE /admin/users/{id}/sessions/{sessionId}`, `DELETE /admin/users/{id}/sessions` | support | end one, or every, session |
| `GET /admin/users/{id}/mfa` | read | the factors, without secrets or destinations |
| `DELETE /admin/users/{id}/mfa/{factorId}` | manage | remove one factor (the last one under enforced MFA is refused: reset instead) |
| `DELETE /admin/users/{id}/mfa` | manage | remove every factor and recovery code |
| `GET /admin/organizations?status=&cursor=&limit=` | read | the organizations |
| `GET /admin/organizations/{id}` | read | one organization with its members and their roles |
| `PATCH /admin/organizations/{id}/members/{userId}/roles` `{roles}` | manage | replace a member's roles (the last owner stays) |
| `DELETE /admin/organizations/{id}` | manage | core's soft deletion |
| `GET /admin/audit?names=&actor_id=&subject_id=&organization_id=&from=&to=&cursor=&limit=` | read | the instance-wide trail (newest first) |
| `GET`, `POST /admin/organizations/{id}/drains` | read, own | the organization's audit drains; a new signed webhook drain (`endpoint`, `secret`, `filter`) |
| `DELETE /admin/organizations/{id}/drains/{drainId}`, `POST .../drains/{drainId}/test` | own | delete; record `admin.drain_tested` and answer the drain's delivery state |
| `GET /admin/stats` | read | totals, sign-ups, sign-ins and active users over 24h, 7d and 30d |
| `GET`, `POST /admin/keys`, `DELETE /admin/keys/{id}` | own | the API keys (the secret is in the creation response only) |
| `GET`, `POST /admin/grants`, `DELETE /admin/grants/{id}` | own | the admin grants |

## Impersonation

`POST /admin/users/{id}/impersonate` answers an access token whose `sub` is the user, with `amr:
["impersonation"]`, `mfa: false`, the `impersonated_by` claim (the operator's id) and `impersonator_type`,
and no session (`sid`) behind it: it cannot be refreshed, stepped up, switched to an organization or logged
out, so it lives exactly one access-token TTL (`auth.access_token.ttl`, 15 minutes by default). It reads and
acts as the user on core's routes, never on the admin routes; a superadmin cannot be impersonated; a
disabled account is refused. Hosts render a banner from the claim.

## Audit

Every mutation is recorded through `polaris/audit` as `admin.<action>` (`admin.user_banned`,
`admin.password_set`, `admin.user_impersonated`, `admin.session_revoked`, `admin.mfa_reset`,
`admin.member_roles_changed`, `admin.organization_deleted`, `admin.drain_created`, `admin.key_created`,
`admin.grant_created`, ...), the operator as actor (`actor_type` `admin` for a user, `api_key` for a key),
the target as subject, the operator's role and scope in `data`, beside the core event the action emits
(`user.disabled`, `mfa.factor_removed`, ...). `GET /audit/types` lists the names.

## CLI

`polaris admin:key <name> <role> [--scope=] [--allow=cidr,...] [--expires=]` prints the key once;
`polaris admin:grant <email> <role> [--scope=] [--expires=]` grants a role. Both take `--bootstrap=<file>`
(or `POLARIS_BOOTSTRAP`) naming the application, as the other Polaris commands.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
