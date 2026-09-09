<?php

declare(strict_types=1);

namespace Polaris\Cli\Command;

use Polaris\Cli\Database;
use Polaris\Config\EnvironmentConfig;
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
            $secrets = EnvironmentConfig::secrets();
            $this->report($output, true, 'secrets: APP_KEY, AUTH_JWT_PRIVATE_KEY, AUTH_JWT_PUBLIC_KEY, AUTH_JWT_KID present');
            $this->report($output, openssl_pkey_get_private($secrets->jwtPrivateKey) !== false, 'keys: AUTH_JWT_PRIVATE_KEY parses');
            $this->report($output, openssl_pkey_get_public($secrets->jwtPublicKey) !== false, 'keys: AUTH_JWT_PUBLIC_KEY parses');
            if ($secrets->jwtPreviousPublicKey !== null) {
                $this->report($output, openssl_pkey_get_public($secrets->jwtPreviousPublicKey) !== false && $secrets->jwtPreviousKid !== null, 'keys: previous public key parses and has a kid');
            }
        } catch (Throwable $exception) {
            $this->report($output, false, 'secrets: ' . $exception->getMessage());
        }

        try {
            $auth = EnvironmentConfig::auth();
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
        if ($dsn === null) {
            $output->writeln(' - database: skipped (pass --dsn or set POLARIS_DSN)');
        } else {
            try {
                $pdo = Database::connect($dsn, $input->getOption('user'), $input->getOption('password'));
                $pdo->query('SELECT 1');
                $this->report($output, true, 'database: connected');
                $differences = (new SchemaDiff(new SchemaInspector($pdo, Database::dialect($dsn)), Database::dialect($dsn)))->run();
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
