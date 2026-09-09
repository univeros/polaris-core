<?php

declare(strict_types=1);

namespace Polaris\Wiring;

use Polaris\Config\AuthConfig;
use Polaris\Config\RateLimitConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\BreachedPasswordCheckInterface;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\EncrypterInterface;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Contract\QrCodeRendererInterface;
use Polaris\Contract\RateStore;
use Polaris\Contract\SmsSenderInterface;
use Polaris\Contract\TotpProviderInterface;
use Polaris\Http\Manifest\Loader;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Everything an application hands Polaris: its secrets and auth settings, the database
 * adapter, and the ports it wants to override. Anything null takes the core default.
 */
final readonly class Config
{
    public function __construct(
        public Secrets $secrets,
        public AuthConfig $auth,
        public DatabaseAdapter $database,
        public ?OtpMailerInterface $mailer = null,
        public ?SmsSenderInterface $sms = null,
        public ?BreachedPasswordCheckInterface $breachCheck = null,
        public ?CacheInterface $cache = null,
        public ?ClockInterface $clock = null,
        public ?EventDispatcherInterface $dispatcher = null,
        public ?LoggerInterface $logger = null,
        public ?RateLimitConfig $rateLimits = null,
        public ?RateStore $rateStore = null,
        public ?EncrypterInterface $encrypter = null,
        public ?TotpProviderInterface $totp = null,
        public ?QrCodeRendererInterface $qrCodes = null,
        public ?ResponseFactoryInterface $responseFactory = null,
        public ?string $manifestDirectory = null,
        public string $pathPrefix = '/',
    ) {
    }

    public function manifestDirectory(): string
    {
        return $this->manifestDirectory ?? Loader::defaultDirectory();
    }
}
