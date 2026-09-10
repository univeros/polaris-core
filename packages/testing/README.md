# polaris/testing

Test support for applications built on [Polaris for PHP](https://github.com/univeros/polaris-core):
`InMemoryAdapter`, a `Polaris\Contract\DatabaseAdapter` over PHP arrays with the same
criteria, ordering, limit, increment and transaction semantics as `polaris/pdo`, so auth flows
can be tested without a database.

## Install

```sh
composer require --dev polaris/testing
```

## Use

```php
use Polaris\Testing\InMemoryAdapter;

$polaris = Polaris::create(new Config(
    secrets: $secrets,
    auth: $auth,
    database: new InMemoryAdapter(),
));
```

Seed the permission catalog and system roles as in production
(`Polaris\Authorization\PermissionCatalogSeeder`), then drive the services or the HTTP
pipeline. Transactions roll back on exceptions, as the PDO adapter's do.

## License

MIT.
