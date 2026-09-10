<?php

declare(strict_types=1);

namespace Polaris\Laravel;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Events\Dispatcher as IlluminateDispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Mail\Mailer as MailerContract;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Database\DatabaseManager;
use Illuminate\Log\LogManager;
use Polaris\Config\AuthConfig;
use Polaris\Config\RateLimitConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\BreachedPasswordCheckInterface;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\EncrypterInterface;
use Polaris\Contract\MetricsInterface;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Contract\QrCodeRendererInterface;
use Polaris\Contract\RateStore;
use Polaris\Contract\SmsSenderInterface;
use Polaris\Contract\TotpProviderInterface;
use Polaris\Exception\InvalidConfigException;
use Polaris\Laravel\Events\EventBridge;
use Polaris\Laravel\Mail\OtpMailer;
use Polaris\Pdo\PdoAdapter;
use Polaris\Polaris;
use Polaris\Wiring\Config;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

use function file_get_contents;
use function get_debug_type;
use function in_array;
use function is_array;
use function is_string;
use function is_file;
use function sprintf;
use function str_starts_with;
use function strtolower;

/**
 * Builds {@see Polaris} from the `polaris` configuration (config/polaris.php) and the application's
 * services: the database connection, cache, logger, events and mailer are Laravel's. Every port takes
 * null (the core default), a class name or container binding, or an object.
 */
final readonly class PolarisFactory
{
    private const array SECRET_KEYS = [
        'app_key' => 'APP_KEY',
        'jwt_private_key' => 'AUTH_JWT_PRIVATE_KEY',
        'jwt_public_key' => 'AUTH_JWT_PUBLIC_KEY',
        'jwt_kid' => 'AUTH_JWT_KID',
        'jwt_previous_public_key' => 'AUTH_JWT_PREVIOUS_PUBLIC_KEY',
        'jwt_previous_kid' => 'AUTH_JWT_PREVIOUS_KID',
    ];
    private const array FLAGS = ['access_token' => 'denylist', 'password' => 'breach_check'];

    public function __construct(private Application $app)
    {
    }

    /**
     * @param array<string, mixed> $config
     */
    public function create(array $config): Polaris
    {
        return Polaris::create(new Config(
            secrets: $this->secrets($config['secrets'] ?? []),
            auth: $this->auth($config['auth'] ?? []),
            database: $this->database($config['database'] ?? null),
            mailer: $this->mailer($config['mailer'] ?? 'log'),
            sms: $this->sms($config['sms'] ?? 'log'),
            breachCheck: $this->port($config['breach_check'] ?? null, BreachedPasswordCheckInterface::class, 'breach_check'),
            cache: $this->cache($config['cache'] ?? null),
            clock: $this->port($config['clock'] ?? null, ClockInterface::class, 'clock'),
            dispatcher: $this->dispatcher($config['dispatcher'] ?? null),
            logger: $this->logger($config['log'] ?? null),
            rateLimits: $this->rateLimits($config['rate_limits'] ?? []),
            rateStore: $this->port($config['rate_store'] ?? null, RateStore::class, 'rate_store'),
            encrypter: $this->port($config['encrypter'] ?? null, EncrypterInterface::class, 'encrypter'),
            metrics: $this->port($config['metrics'] ?? null, MetricsInterface::class, 'metrics'),
            totp: $this->port($config['totp'] ?? null, TotpProviderInterface::class, 'totp'),
            qrCodes: $this->port($config['qr_codes'] ?? null, QrCodeRendererInterface::class, 'qr_codes'),
            manifestDirectory: self::string($config['manifest_directory'] ?? null),
            pathPrefix: self::string($config['path_prefix'] ?? null) ?? '/',
        ));
    }

    private function secrets(mixed $secrets): Secrets
    {
        if ($secrets instanceof Secrets) {
            return $secrets;
        }
        if (!is_array($secrets)) {
            throw new InvalidConfigException('polaris.secrets must be an array or a Polaris\Config\Secrets.');
        }
        $env = [];
        foreach (self::SECRET_KEYS as $key => $name) {
            $value = self::string($secrets[$key] ?? null) ?? $this->file(self::string($secrets[$key . '_file'] ?? null), $key);
            if ($value !== null) {
                $env[$name] = $value;
            }
        }

        return Secrets::fromEnvironment($env);
    }

    private function file(?string $path, string $key): ?string
    {
        if ($path === null) {
            return null;
        }
        $absolute = str_starts_with($path, '/') ? $path : $this->app->basePath($path);
        if (!is_file($absolute)) {
            throw new InvalidConfigException(sprintf('polaris.secrets.%s_file points to a missing file: %s', $key, $absolute));
        }

        return (string) file_get_contents($absolute);
    }

    private function auth(mixed $auth): AuthConfig
    {
        if ($auth instanceof AuthConfig) {
            return $auth;
        }
        if (!is_array($auth)) {
            throw new InvalidConfigException('polaris.auth must be an array or a Polaris\Config\AuthConfig.');
        }
        // `env()` hands the two flags over as strings; core reads "1", "true" and "on" as set.
        $normalised = $auth;
        foreach (self::FLAGS as $section => $flag) {
            $value = $normalised[$section][$flag] ?? null;
            if (is_string($value)) {
                $normalised[$section][$flag] = in_array(strtolower($value), ['1', 'true', 'on'], true);
            }
        }

        return AuthConfig::fromArray($normalised);
    }

    private function rateLimits(mixed $limits): RateLimitConfig
    {
        if ($limits instanceof RateLimitConfig) {
            return $limits;
        }

        return RateLimitConfig::fromArray(is_array($limits) ? $limits : []);
    }

    private function database(mixed $database): DatabaseAdapter
    {
        if ($database instanceof DatabaseAdapter) {
            return $database;
        }

        return new PdoAdapter($this->app->make(DatabaseManager::class)->connection(self::string($database))->getPdo());
    }

    private function cache(mixed $cache): CacheInterface
    {
        if ($cache instanceof CacheInterface) {
            return $cache;
        }

        return $this->app->make(CacheFactory::class)->store(self::string($cache));
    }

    private function logger(mixed $log): LoggerInterface
    {
        if ($log instanceof LoggerInterface) {
            return $log;
        }
        $channel = self::string($log);

        return $channel === null ? $this->app->make(LoggerInterface::class) : $this->app->make(LogManager::class)->channel($channel);
    }

    private function dispatcher(mixed $dispatcher): EventDispatcherInterface
    {
        if ($dispatcher instanceof EventDispatcherInterface) {
            return $dispatcher;
        }

        return new EventBridge($this->app->make(IlluminateDispatcher::class), fn (): array => $this->app->make(Polaris::class)->listeners());
    }

    private function mailer(mixed $mailer): ?OtpMailerInterface
    {
        if ($mailer === null || $mailer === 'log') {
            return null;
        }
        if ($mailer === 'mail') {
            return new OtpMailer($this->app->make(MailerContract::class), $this->app->make(ViewFactory::class));
        }

        return $this->port($mailer, OtpMailerInterface::class, 'mailer');
    }

    private function sms(mixed $sms): ?SmsSenderInterface
    {
        return $sms === null || $sms === 'log' ? null : $this->port($sms, SmsSenderInterface::class, 'sms');
    }

    /**
     * @template T of object
     * @param class-string<T> $type
     * @return T|null
     */
    private function port(mixed $value, string $type, string $key): ?object
    {
        if ($value === null) {
            return null;
        }
        $service = is_string($value) ? $this->app->make($value) : $value;
        if (!$service instanceof $type) {
            throw new InvalidConfigException(sprintf('polaris.%s must be a %s, got %s.', $key, $type, get_debug_type($service)));
        }

        return $service;
    }

    private static function string(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
