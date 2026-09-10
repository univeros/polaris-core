<?php

declare(strict_types=1);

namespace Polaris\Yii\Tests;

use HttpSoft\Message\StreamFactory;
use Override;
use Polaris\Config\AuthConfig;
use Polaris\Config\RateLimitConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Contract\SmsSenderInterface;
use Polaris\Support\InMemoryCache;
use Polaris\Tests\Functional\Harness as HarnessContract;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\SimpleCache\CacheInterface;
use Yiisoft\Di\Container;

use function is_array;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * The functional suite through Yii (docs/adapters/spec.md §3.7): a real `Yiisoft\Yii\Http\Application`
 * on the package's definitions, the test's instances as the container's definitions, every request
 * pushed through the application as bytes (`RequestBodyParser` parses them, as in a Yii host).
 * `POLARIS_HARNESS=Polaris\Yii\Tests\Harness`.
 */
final class Harness implements HarnessContract
{
    private function __construct(private readonly Container $container)
    {
    }

    #[Override]
    public static function create(Config $config): static
    {
        $container = YiiApp::container(
            polaris: [
                'path_prefix' => $config->pathPrefix,
                'manifest_directory' => $config->manifestDirectory,
                'mailer' => OtpMailerInterface::class,
                'sms' => SmsSenderInterface::class,
            ],
            definitions: [
                Secrets::class => $config->secrets,
                AuthConfig::class => $config->auth,
                RateLimitConfig::class => $config->rateLimits ?? RateLimitConfig::defaults(),
                DatabaseAdapter::class => $config->database,
                OtpMailerInterface::class => $config->mailer,
                SmsSenderInterface::class => $config->sms,
                EventDispatcherInterface::class => $config->dispatcher,
                CacheInterface::class => $config->cache ?? new InMemoryCache(),
            ],
        );

        return new self($container);
    }

    #[Override]
    public function graph(): Graph
    {
        return $this->container->get(Graph::class);
    }

    #[Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return YiiApp::handle($this->container, self::wire($request));
    }

    /**
     * PSR-7 end to end: Yii adds nothing to a response.
     */
    #[Override]
    public static function transportHeaders(): array
    {
        return [];
    }

    /**
     * The tests build requests with a parsed body and no bytes; a client sends bytes, which the
     * application's `RequestBodyParser` parses.
     */
    private static function wire(ServerRequestInterface $request): ServerRequestInterface
    {
        $parsed = $request->getParsedBody();
        if (is_array($parsed) && $parsed !== [] && (string) $request->getBody() === '') {
            $request = $request
                ->withBody((new StreamFactory())->createStream(json_encode($parsed, JSON_THROW_ON_ERROR)))
                ->withParsedBody(null);
            if (!$request->hasHeader('Content-Type')) {
                $request = $request->withHeader('Content-Type', 'application/json');
            }
        }

        return $request;
    }
}
