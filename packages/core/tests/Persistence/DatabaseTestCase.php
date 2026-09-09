<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use DateTimeImmutable;
use PDO;
use PHPUnit\Framework\TestCase;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\PermissionCatalogSeeder;
use Polaris\Contract\Dialect;
use Polaris\Pdo\PdoAdapter;
use Polaris\Pdo\SqlSchema;
use Polaris\Repository\IdentityMap;
use Polaris\Repository\UnitOfWork;
use RuntimeException;

use function array_map;
use function array_values;
use function explode;
use function getenv;
use function in_array;
use function ksort;
use function preg_match;
use function sprintf;
use function trim;

/**
 * Base class for Polaris persistence tests: the Polaris schema on a real database through the
 * PDO adapter, rebuilt for every test and seeded with the permission catalog and system roles.
 *
 * The driver comes from the environment (`DB_CONNECTION`, `DB_DATABASE`, `DB_HOST`, `DB_PORT`,
 * `DB_USER`, `DB_PASSWORD`); CI exports PostgreSQL. Without `DB_CONNECTION` the tests run on an
 * in-memory SQLite database, so the whole suite runs locally in seconds.
 */
abstract class DatabaseTestCase extends TestCase
{
    protected PdoAdapter $adapter;
    protected IdentityMap $identities;
    protected UnitOfWork $unitOfWork;

    protected function setUp(): void
    {
        $this->adapter = new PdoAdapter(self::connect());
        $this->rebuildSchema();
        $this->identities = new IdentityMap();
        $this->unitOfWork = new UnitOfWork($this->adapter, $this->identities);
    }

    protected function tearDown(): void
    {
        if ($this->adapter->dialect() !== Dialect::Sqlite) {
            foreach (SqlSchema::dropAll($this->adapter->dialect()) as $statement) {
                $this->adapter->exec($statement);
            }
        }
    }

    protected function pdo(): PDO
    {
        return $this->adapter->pdo();
    }

    protected function hasTable(string $table): bool
    {
        $sql = $this->adapter->dialect() === Dialect::Sqlite
            ? "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?"
            : 'SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?';
        $statement = $this->pdo()->prepare($sql);
        $statement->execute([$table]);

        return (int) $statement->fetchColumn() > 0;
    }

    protected function hasColumn(string $table, string $column): bool
    {
        if ($this->adapter->dialect() === Dialect::Sqlite) {
            foreach ($this->pdo()->query(sprintf('PRAGMA table_info("%s")', $table))->fetchAll(PDO::FETCH_ASSOC) as $row) {
                if (($row['name'] ?? null) === $column) {
                    return true;
                }
            }

            return false;
        }
        $statement = $this->pdo()->prepare('SELECT COUNT(*) FROM information_schema.columns WHERE table_name = ? AND column_name = ?');
        $statement->execute([$table, $column]);

        return (int) $statement->fetchColumn() > 0;
    }

    /**
     * @param list<string> $columns in index order
     */
    protected function hasIndex(string $table, array $columns): bool
    {
        return in_array($columns, $this->indexes($table), true);
    }

    /**
     * @return list<string> primary key columns in order
     */
    protected function primaryKey(string $table): array
    {
        $pdo = $this->pdo();
        switch ($this->adapter->dialect()) {
            case Dialect::Sqlite:
                $columns = [];
                foreach ($pdo->query(sprintf('PRAGMA table_info("%s")', $table))->fetchAll(PDO::FETCH_ASSOC) as $row) {
                    if ((int) $row['pk'] > 0) {
                        $columns[(int) $row['pk']] = (string) $row['name'];
                    }
                }
                ksort($columns);

                return array_values($columns);
            case Dialect::Postgres:
                $statement = $pdo->prepare(
                    'SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)'
                    . ' WHERE i.indrelid = ?::regclass AND i.indisprimary ORDER BY array_position(i.indkey, a.attnum)',
                );
                $statement->execute([$table]);

                return array_map(static fn(mixed $c): string => (string) $c, $statement->fetchAll(PDO::FETCH_COLUMN));
            default:
                $columns = [];
                foreach ($pdo->query(sprintf('SHOW INDEX FROM `%s`', $table))->fetchAll(PDO::FETCH_ASSOC) as $row) {
                    if ($row['Key_name'] === 'PRIMARY') {
                        $columns[(int) $row['Seq_in_index']] = (string) $row['Column_name'];
                    }
                }
                ksort($columns);

                return array_values($columns);
        }
    }

    /**
     * @return list<list<string>> the column list of every index on the table
     */
    private function indexes(string $table): array
    {
        $pdo = $this->pdo();
        $indexes = [];
        switch ($this->adapter->dialect()) {
            case Dialect::Sqlite:
                foreach ($pdo->query(sprintf('PRAGMA index_list("%s")', $table))->fetchAll(PDO::FETCH_ASSOC) as $index) {
                    $columns = [];
                    foreach ($pdo->query(sprintf('PRAGMA index_info("%s")', $index['name']))->fetchAll(PDO::FETCH_ASSOC) as $row) {
                        $columns[(int) $row['seqno']] = (string) $row['name'];
                    }
                    ksort($columns);
                    $indexes[] = array_values($columns);
                }
                break;
            case Dialect::Postgres:
                $statement = $pdo->prepare('SELECT indexdef FROM pg_indexes WHERE tablename = ?');
                $statement->execute([$table]);
                foreach ($statement->fetchAll(PDO::FETCH_COLUMN) as $definition) {
                    if (preg_match('/\(([^)]+)\)/', (string) $definition, $match) === 1) {
                        $indexes[] = array_map(static fn(string $c): string => trim($c, ' "'), explode(',', $match[1]));
                    }
                }
                break;
            default:
                $byName = [];
                foreach ($pdo->query(sprintf('SHOW INDEX FROM `%s`', $table))->fetchAll(PDO::FETCH_ASSOC) as $row) {
                    $byName[(string) $row['Key_name']][(int) $row['Seq_in_index']] = (string) $row['Column_name'];
                }
                foreach ($byName as $columns) {
                    ksort($columns);
                    $indexes[] = array_values($columns);
                }
        }

        return $indexes;
    }

    /**
     * Seeds the permission catalog and system roles, as the 1.0 seed migration did.
     */
    protected function seedCatalog(?DateTimeImmutable $now = null): void
    {
        (new PermissionCatalogSeeder(new PermissionCatalog()))->seed($this->adapter, $now ?? new DateTimeImmutable('now'));
    }

    private function rebuildSchema(): void
    {
        foreach (SqlSchema::dropAll($this->adapter->dialect()) as $statement) {
            $this->adapter->exec($statement);
        }
        foreach (SqlSchema::createAll($this->adapter->dialect()) as $statement) {
            $this->adapter->exec($statement);
        }
        $this->seedCatalog();
    }

    private static function connect(): PDO
    {
        $env = static fn(string $key, string $default = ''): string => (($value = getenv($key)) === false || $value === '') ? $default : $value;
        $driver = $env('DB_CONNECTION');

        if ($driver === '' || $driver === 'sqlite') {
            $pdo = new PDO('sqlite:' . $env('DB_DATABASE', ':memory:'));
            $pdo->exec('PRAGMA foreign_keys = ON');

            return $pdo;
        }
        if (in_array($driver, ['postgres', 'postgresql', 'pgsql'], true)) {
            return new PDO(
                sprintf('pgsql:host=%s;port=%s;dbname=%s', $env('DB_HOST', '127.0.0.1'), $env('DB_PORT', '5432'), $env('DB_DATABASE', 'polaris_test')),
                $env('DB_USER', 'postgres'),
                $env('DB_PASSWORD'),
            );
        }
        if ($driver === 'mysql') {
            return new PDO(
                sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', $env('DB_HOST', '127.0.0.1'), $env('DB_PORT', '3306'), $env('DB_DATABASE', 'polaris_test')),
                $env('DB_USER', 'root'),
                $env('DB_PASSWORD'),
            );
        }

        throw new RuntimeException(sprintf('Unsupported DB_CONNECTION "%s"; use postgres, mysql or sqlite.', $driver));
    }
}
