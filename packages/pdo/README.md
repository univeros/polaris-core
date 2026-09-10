# polaris/pdo

The PDO database adapter for [Polaris for PHP](https://github.com/univeros/polaris-core):
PostgreSQL, MySQL and SQLite through prepared statements, savepoints for nested transactions,
plus the DDL exporter and the schema inspector behind `polaris schema:export` and
`schema:diff`.

## Install

```sh
composer require polaris/pdo
```

## Use

```php
use Polaris\Pdo\PdoAdapter;

$pdo = new PDO('pgsql:host=localhost;dbname=app', $user, $password);
$adapter = new PdoAdapter($pdo);   // the dialect is detected from the driver

$polaris = Polaris::create(new Config(database: $adapter, /* ... */));
```

Create the tables once from the schema (or run `polaris schema:export --target=sql:postgres`
from `polaris/cli` and apply the output with your migration tool):

```php
use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\PermissionCatalogSeeder;
use Polaris\Contract\Dialect;
use Polaris\Pdo\SqlSchema;

foreach (SqlSchema::createAll(Dialect::Postgres) as $statement) {
    $adapter->exec($statement);
}
(new PermissionCatalogSeeder(new PermissionCatalog()))->seed($adapter, new DateTimeImmutable());
```

Dialects: `Dialect::Postgres`, `Dialect::Mysql`, `Dialect::Sqlite` (turn `PRAGMA foreign_keys`
on). The adapter passes the Polaris conformance suite on all three.

## License

MIT.
