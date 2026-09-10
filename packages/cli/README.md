# polaris/cli

`bin/polaris`, the command line of [Polaris for PHP](https://github.com/univeros/polaris-core).

## Install

```sh
composer require polaris/cli
```

## Commands

| Command | What it does |
| --- | --- |
| `polaris schema:export --target=sql:postgres\|sql:mysql\|sql:sqlite [--drop]` | Prints the DDL for the Polaris tables |
| `polaris schema:diff --dsn=...` | Compares a live database with the schema Polaris needs |
| `polaris manifest --format=json\|openapi [--dir=...]` | Validates the endpoint specs and renders them as JSON or OpenAPI 3.1 |
| `polaris doctor [--dsn=...]` | Checks secrets and keys, auth settings, the manifest, database connectivity and the schema |

The connection comes from `--dsn`, or from `POLARIS_DSN` with `POLARIS_DB_USER` and
`POLARIS_DB_PASSWORD`; secrets and settings come from the environment variables Polaris reads
(`APP_KEY`, `AUTH_JWT_PRIVATE_KEY`, `AUTH_JWT_PUBLIC_KEY`, `AUTH_JWT_KID`, `AUTH_ISSUER`,
`AUTH_AUDIENCE`, ...).

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
