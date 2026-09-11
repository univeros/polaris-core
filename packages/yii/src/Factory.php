<?php

declare(strict_types=1);

namespace Polaris\Yii;

use PDO;
use Polaris\Config\AuthConfig;
use Polaris\Config\RateLimitConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\BreachedPasswordCheckInterface;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\EncrypterInterface;
use Polaris\Contract\MetricsInterface;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Http\Manifest\Loader;
use Polaris\Contract\Plugin;
use Polaris\Contract\QrCodeRendererInterface;
use Polaris\Contract\RateStore;
use Polaris\Contract\SmsSenderInterface;
use Polaris\Contract\TotpProviderInterface;
use Polaris\Exception\InvalidConfigException;
use Polaris\Pdo\PdoAdapter;
use Polaris\Wiring\Config;
use Polaris\Yii\Mail\OtpMailer;
use Psr\Clock\ClockInterface;
use Psr\Container\ContainerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

use function file_get_contents;
use function get_debug_type;
use function getcwd;
use function is_array;
use function is_subclass_of;
use function is_file;
use function is_string;
use function method_exists;
use function sprintf;
use function str_starts_with;

/**
 * What config/di.php builds: the secrets from the params (values or PEM files), the PDO handle from
 * the DSN or from the application's connection service, and the {@see Config} from the params and the
 * container's services (cache, logger, dispatcher, mailer, SMS sender, ports).
 */
final class Factory
{
    private const array SECRET_KEYS = [
        'app_key' => 'APP_KEY',
        'jwt_private_key' => 'AUTH_JWT_PRIVATE_KEY',
        'jwt_public_key' => 'AUTH_JWT_PUBLIC_KEY',
        'jwt_kid' => 'AUTH_JWT_KID',
        'jwt_previous_public_key' => 'AUTH_JWT_PREVIOUS_PUBLIC_KEY',
        'jwt_previous_kid' => 'AUTH_JWT_PREVIOUS_KID',
    ];
    private const string YII_DB_CONNECTION = 'Yiisoft\Db\Connection\ConnectionInterface';

    /**
     * @param array<string, mixed> $secrets
     */
    public static function secrets(array $secrets, ?string $rootPath): Secrets
    {
        $root = $rootPath ?? (string) getcwd();
        $env = [];
        foreach (self::SECRET_KEYS as $key => $name) {
            $value = self::string($secrets[$key] ?? null) ?? self::file(self::string($secrets[$key . '_file'] ?? null), $key, $root);
            if ($value !== null) {
                $env[$name] = $value;
            }
        }

        return Secrets::fromEnvironment($env);
    }

    public static function connect(string $dsn, ?string $user, ?string $password): PDO
    {
        $pdo = new PDO($dsn, $user, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        if (str_starts_with($dsn, 'sqlite:')) {
            $pdo->exec('PRAGMA foreign_keys = ON');
        }

        return $pdo;
    }

    /**
     * The application's PDO handle for the database adapter: the `PDO` service (config/di.php defines
     * it from `database.dsn`) or a `Yiisoft\Db` connection.
     */
    public static function pdo(ContainerInterface $container): PDO
    {
        if ($container->has(PDO::class)) {
            return $container->get(PDO::class);
        }
        if ($container->has(self::YII_DB_CONNECTION)) {
            $connection = $container->get(self::YII_DB_CONNECTION);
            if (method_exists($connection, 'getPDO')) {
                $pdo = $connection->getPDO();
                if ($pdo instanceof PDO) {
                    return $pdo;
                }
            }
        }

        throw new InvalidConfigException('Polaris needs a database: set polaris.database.dsn in the params, or define a PDO or Yiisoft\Db connection in the container.');
    }

    /**
     * The PDO handle for the console commands: {@see pdo()}, or the one behind the application's own
     * `DatabaseAdapter` definition.
     */
    public static function connection(ContainerInterface $container): PDO
    {
        if ($container->has(PDO::class) || $container->has(self::YII_DB_CONNECTION)) {
            return self::pdo($container);
        }
        $adapter = $container->get(DatabaseAdapter::class);
        if ($adapter instanceof PdoAdapter) {
            return $adapter->pdo();
        }

        throw new InvalidConfigException('The console commands need a PDO connection: set polaris.database.dsn in the params, or define a PDO or Yiisoft\Db connection in the container.');
    }

    /**
     * @param array<string, mixed> $polaris the `polaris` params
     */
    public static function config(ContainerInterface $container, array $polaris): Config
    {
        return new Config(
            secrets: $container->get(Secrets::class),
            auth: $container->get(AuthConfig::class),
            database: $container->get(DatabaseAdapter::class),
            mailer: self::mailer($container, $polaris['mailer'] ?? 'log'),
            sms: self::port($container, $polaris['sms'] ?? 'log', SmsSenderInterface::class, 'sms'),
            breachCheck: self::port($container, $polaris['breach_check'] ?? null, BreachedPasswordCheckInterface::class, 'breach_check'),
            cache: $container->has(CacheInterface::class) ? $container->get(CacheInterface::class) : null,
            clock: self::port($container, $polaris['clock'] ?? null, ClockInterface::class, 'clock'),
            dispatcher: $container->has(EventDispatcherInterface::class) ? $container->get(EventDispatcherInterface::class) : null,
            logger: $container->has(LoggerInterface::class) ? $container->get(LoggerInterface::class) : null,
            rateLimits: $container->get(RateLimitConfig::class),
            rateStore: self::port($container, $polaris['rate_store'] ?? null, RateStore::class, 'rate_store'),
            encrypter: self::port($container, $polaris['encrypter'] ?? null, EncrypterInterface::class, 'encrypter'),
            metrics: self::port($container, $polaris['metrics'] ?? null, MetricsInterface::class, 'metrics'),
            totp: self::port($container, $polaris['totp'] ?? null, TotpProviderInterface::class, 'totp'),
            qrCodes: self::port($container, $polaris['qr_codes'] ?? null, QrCodeRendererInterface::class, 'qr_codes'),
            manifestDirectory: self::string($polaris['manifest_directory'] ?? null),
            pathPrefix: self::string($polaris['path_prefix'] ?? null) ?? '/',
            plugins: self::plugins($container, $polaris['plugins'] ?? []),
        );
    }

    /**
     * Core's manifest directory and every plugin's, for config/routes.php, which only has the params:
     * a plugin entry is a class name or an instance there (a container id has no static answer).
     *
     * @param array<string, mixed> $polaris the `polaris` params
     * @return list<string>
     */
    public static function manifestDirectories(array $polaris): array
    {
        $directories = [self::string($polaris['manifest_directory'] ?? null) ?? Loader::defaultDirectory()];
        foreach (is_array($polaris['plugins'] ?? null) ? $polaris['plugins'] : [] as $plugin) {
            if ($plugin instanceof Plugin || (is_string($plugin) && is_subclass_of($plugin, Plugin::class))) {
                $directory = $plugin::manifestDirectory();
                if ($directory !== null) {
                    $directories[] = $directory;
                }
            }
        }

        return $directories;
    }

    /**
     * @return list<Plugin>
     */
    private static function plugins(ContainerInterface $container, mixed $plugins): array
    {
        if (!is_array($plugins)) {
            throw new InvalidConfigException('polaris.plugins must be a list of plugin class names, container ids or instances.');
        }
        $instances = [];
        foreach ($plugins as $plugin) {
            $instance = is_string($plugin) ? $container->get($plugin) : $plugin;
            if (!$instance instanceof Plugin) {
                throw new InvalidConfigException(sprintf('polaris.plugins entries must be Polaris\\Contract\\Plugin instances, got %s.', get_debug_type($instance)));
            }
            $instances[] = $instance;
        }

        return $instances;
    }

    private static function mailer(ContainerInterface $container, mixed $mailer): ?OtpMailerInterface
    {
        if ($mailer === 'mail') {
            return $container->get(OtpMailer::class);
        }

        return self::port($container, $mailer, OtpMailerInterface::class, 'mailer');
    }

    /**
     * @template T of object
     * @param class-string<T> $type
     * @return T|null
     */
    private static function port(ContainerInterface $container, mixed $id, string $type, string $key): ?object
    {
        if ($id === null || $id === 'log') {
            return null;
        }
        $service = is_string($id) ? $container->get($id) : $id;
        if (!$service instanceof $type) {
            throw new InvalidConfigException(sprintf('polaris.%s must be a %s, got %s.', $key, $type, get_debug_type($service)));
        }

        return $service;
    }

    private static function file(?string $path, string $key, string $root): ?string
    {
        if ($path === null) {
            return null;
        }
        $absolute = str_starts_with($path, '/') ? $path : $root . '/' . $path;
        if (!is_file($absolute)) {
            throw new InvalidConfigException(sprintf('polaris.secrets.%s_file points to a missing file: %s', $key, $absolute));
        }

        return (string) file_get_contents($absolute);
    }

    private static function string(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
