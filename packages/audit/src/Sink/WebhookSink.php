<?php

declare(strict_types=1);

namespace Polaris\Audit\Sink;

use Closure;
use Override;
use Polaris\Audit\Model\AuditEvent;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use RuntimeException;
use Symfony\Component\Uid\Uuid;

use function array_map;
use function hash_hmac;
use function json_encode;
use function sprintf;
use function usleep;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * POSTs a batch of events as JSON to one endpoint through a PSR-18 client, the body signed with
 * HMAC-SHA256 (`X-Polaris-Signature: sha256=<hex>`), each delivery identified
 * (`X-Polaris-Delivery`); a transport failure, a 429 or a 5xx is retried with a growing pause.
 */
final class WebhookSink implements AuditSink
{
    public const string SIGNATURE_HEADER = 'X-Polaris-Signature';
    public const string DELIVERY_HEADER = 'X-Polaris-Delivery';

    /** @var Closure(int): void */
    private readonly Closure $sleeper;

    /**
     * @param callable(int): void|null $sleeper receives the pause in milliseconds; tests pass a no-op
     */
    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
        private readonly string $url,
        #[\SensitiveParameter] private readonly string $secret,
        private readonly int $attempts = 3,
        ?callable $sleeper = null,
    ) {
        $this->sleeper = $sleeper === null ? static function (int $milliseconds): void {
            usleep($milliseconds * 1000);
        } : $sleeper(...);
    }

    #[Override]
    public function write(AuditEvent ...$events): void
    {
        if ($events === []) {
            return;
        }
        $body = json_encode(['events' => array_map(static fn(AuditEvent $event): array => $event->toArray(), $events)], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $delivery = Uuid::v7()->toRfc4122();
        $last = 'no attempt made';
        for ($attempt = 1; $attempt <= $this->attempts; ++$attempt) {
            try {
                $request = $this->requests->createRequest('POST', $this->url)
                    ->withHeader('Content-Type', 'application/json')
                    ->withHeader(self::DELIVERY_HEADER, $delivery)
                    ->withHeader(self::SIGNATURE_HEADER, 'sha256=' . hash_hmac('sha256', $body, $this->secret))
                    ->withBody($this->streams->createStream($body));
                $status = $this->client->sendRequest($request)->getStatusCode();
                if ($status < 300) {
                    return;
                }
                $last = sprintf('HTTP %d', $status);
                if ($status !== 429 && $status < 500) {
                    break;
                }
            } catch (ClientExceptionInterface $exception) {
                $last = $exception->getMessage();
            }
            if ($attempt < $this->attempts) {
                ($this->sleeper)($attempt * 200);
            }
        }

        throw new RuntimeException(sprintf('Audit webhook %s failed after %d attempt(s): %s', $this->url, $this->attempts, $last));
    }
}
