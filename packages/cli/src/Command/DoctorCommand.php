<?php

declare(strict_types=1);

namespace Polaris\Cli\Command;

use Closure;
use PDO;
use Polaris\Cli\Database;
use Polaris\Config\AuthConfig;
use Polaris\Config\EnvironmentConfig;
use Polaris\Config\Secrets;
use Polaris\Http\Manifest\Loader;
use Polaris\Pdo\SchemaDiff;
use Polaris\Pdo\SchemaInspector;
use Polaris\Psr15\Router;
use Polaris\Token\JwtSignerFactory;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

use function count;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function sprintf;

/**
 * Checks a deployment: secrets and keys, auth settings, database connectivity and schema, manifest.
 */
final class DoctorCommand extends Command
{
    private bool $healthy = true;
    private readonly ?Closure $secrets;
    private readonly ?Closure $auth;
    private readonly ?Closure $connection;

    /**
     * A host passes its own configuration and connection; without them the environment is read, as
     * `bin/polaris` does.
     *
     * @param (callable(): Secrets)|null $secrets
     * @param (callable(): AuthConfig)|null $auth
     * @param (callable(): PDO)|null $connection used when no `--dsn` is given
     */
    public function __construct(?callable $secrets = null, ?callable $auth = null, ?callable $connection = null)
    {
        $this->secrets = $secrets === null ? null : $secrets(...);
        $this->auth = $auth === null ? null : $auth(...);
        $this->connection = $connection === null ? null : $connection(...);
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName('doctor')
            ->setDescription('Checks configuration, keys, database and manifest.')
            ->addOption('dsn', null, InputOption::VALUE_REQUIRED, 'PDO DSN (or POLARIS_DSN); the database check is skipped without one')
            ->addOption('user', null, InputOption::VALUE_REQUIRED, 'Database user (or POLARIS_DB_USER)')
            ->addOption('password', null, InputOption::VALUE_REQUIRED, 'Database password (or POLARIS_DB_PASSWORD)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->healthy = true;

        try {
            $secrets = $this->secrets === null ? EnvironmentConfig::secrets() : ($this->secrets)();
            $this->report($output, true, 'secrets: app key, JWT private key, JWT public key and kid present');
            $this->report($output, openssl_pkey_get_private($secrets->jwtPrivateKey) !== false, 'keys: AUTH_JWT_PRIVATE_KEY parses');
            $this->report($output, openssl_pkey_get_public($secrets->jwtPublicKey) !== false, 'keys: AUTH_JWT_PUBLIC_KEY parses');
            if ($secrets->jwtPreviousPublicKey !== null) {
                $this->report($output, openssl_pkey_get_public($secrets->jwtPreviousPublicKey) !== false && $secrets->jwtPreviousKid !== null, 'keys: previous public key parses and has a kid');
            }
        } catch (Throwable $exception) {
            $this->report($output, false, 'secrets: ' . $exception->getMessage());
        }

        try {
            $auth = $this->auth === null ? EnvironmentConfig::auth() : ($this->auth)();
            JwtSignerFactory::create($auth->accessToken->signer);
            $this->report($output, true, sprintf('auth: issuer "%s", signer %s, access token ttl %ds', $auth->issuer, $auth->accessToken->signer, $auth->accessToken->ttl));
        } catch (Throwable $exception) {
            $this->report($output, false, 'auth: ' . $exception->getMessage());
        }

        try {
            $manifest = (new Loader(Loader::defaultDirectory()))->load();
            new Router($manifest);
            $this->report($output, true, sprintf('manifest: %d endpoints load and route', count($manifest->endpoints())));
        } catch (Throwable $exception) {
            $this->report($output, false, 'manifest: ' . $exception->getMessage());
        }

        $dsn = Database::dsn($input->getOption('dsn'));
        if ($dsn === null && $this->connection === null) {
            $output->writeln(' - database: skipped (pass --dsn or set POLARIS_DSN)');
        } else {
            try {
                $pdo = $dsn === null ? ($this->connection)() : Database::connect($dsn, $input->getOption('user'), $input->getOption('password'));
                $dialect = $dsn === null ? Database::dialectOf($pdo) : Database::dialect($dsn);
                $pdo->query('SELECT 1');
                $this->report($output, true, 'database: connected');
                $differences = (new SchemaDiff(new SchemaInspector($pdo, $dialect), $dialect))->run();
                $this->report($output, $differences === [], $differences === [] ? 'schema: matches the Polaris schema' : sprintf('schema: %d difference(s), run schema:diff', count($differences)));
            } catch (Throwable $exception) {
                $this->report($output, false, 'database: ' . $exception->getMessage());
            }
        }

        $output->writeln($this->healthy ? '<info>Polaris is ready.</info>' : '<error>Polaris is not ready.</error>');

        return $this->healthy ? Command::SUCCESS : Command::FAILURE;
    }

    private function report(OutputInterface $output, bool $ok, string $message): void
    {
        $this->healthy = $this->healthy && $ok;
        $output->writeln(sprintf(' %s %s', $ok ? '<info>ok</info>  ' : '<error>FAIL</error>', $message));
    }
}
