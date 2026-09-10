# Polaris for PHP on Slim 4

The smallest complete host: Slim 4, `polaris/psr15` for the HTTP layer, `polaris/pdo` on a
SQLite file, emails written to `var/mail.log`. Ten minutes from a clean clone to a user with
TOTP in an organization.

```sh
cd examples/slim
composer install
bin/setup                       # .env, RS256 keys, SQLite schema, permission catalog
php -S 127.0.0.1:8080 -t public # in another terminal
bin/walkthrough.sh              # the steps below, executed
```

`bin/walkthrough.sh` starts its own server when none is running, so `composer install && bin/setup && bin/walkthrough.sh` is enough.

## The walkthrough by hand

```sh
URL=http://127.0.0.1:8080

# 1. Register. The verification email lands in var/mail.log as one JSON line.
curl -s -X POST $URL/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"Sup3r-Secret-Passw0rd"}'
TOKEN=$(tail -1 var/mail.log | php -r 'echo json_decode(stream_get_contents(STDIN), true)["context"]["token"];')

# 2. Verify the email.
curl -s -X POST $URL/auth/email/verify -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\"}"

# 3. Log in: an access token (JWT, 15 minutes) and a rotating refresh token.
curl -s -X POST $URL/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"Sup3r-Secret-Passw0rd"}'
ACCESS=...   # data.access_token from the response

# 4. Enrol a TOTP factor and confirm it with a code from your authenticator (or otphp).
curl -s -X POST $URL/auth/mfa/totp/enroll -H "Authorization: Bearer $ACCESS"
curl -s -X POST $URL/auth/mfa/totp/confirm -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"factor_id":"<factor_id>","code":"<123456>"}'

# 5. Log in again: the password step now answers mfa_required with a short-lived mfa_token.
curl -s -X POST $URL/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"Sup3r-Secret-Passw0rd"}'
curl -s -X POST $URL/auth/mfa/verify -H "Authorization: Bearer <mfa_token>" \
  -H 'Content-Type: application/json' -d '{"factor_id":"<factor_id>","code":"<123456>"}'

# 6. Create an organization; the creator becomes its owner.
curl -s -X POST $URL/orgs -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"name":"Acme Rockets"}'
curl -s $URL/orgs -H "Authorization: Bearer $ACCESS"

# 7. Scope the session to the organization: the new access token carries its roles and
#    permissions, so org-level endpoints such as the member list open up.
curl -s -X POST $URL/auth/switch-org -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"organization_id":"<org id>"}'
curl -s $URL/orgs/<org id>/members -H "Authorization: Bearer <scoped access token>"
```

Every endpoint is declared in `../../packages/core/api/**/*.yaml`; `../../bin/polaris manifest --format=openapi` renders the OpenAPI document, `bin/polaris doctor --dsn=sqlite:var/polaris.sqlite` (with the `.env` loaded) checks the deployment.

## What the host provides

`src/bootstrap.php` is the whole integration:

- `Polaris::create(new Config(...))` with the secrets and settings from the environment, a `PdoAdapter`, a mailer, and a PSR-14 dispatcher that gets `$polaris->listeners()` (audit log, notifications, metrics).
- `new Pipeline($polaris->graph(), $responseFactory)`: its `middleware()` goes on the Slim app (reversed, because Slim runs the last-added middleware first) and its `handler()` serves every route.

Swap the SQLite DSN for PostgreSQL or MySQL, the file mailer for your transport, and the dispatcher for your own, and the same code runs in production.

Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
