<?php

declare(strict_types=1);

namespace Polaris\Audit\Drain;

use Closure;
use Override;
use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Sink\AuditSink;
use Polaris\Audit\Sink\WebhookSink;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Throwable;

use function array_filter;
use function array_values;

/**
 * Delivers each organization's events to that organization's active drains, through a
 * {@see WebhookSink} per drain, and records the outcome on the drain; a failing drain never affects
 * the others or the operation.
 */
final class DrainSink implements AuditSink
{
    private readonly ?Closure $sleeper;

    /**
     * @param callable(int): void|null $sleeper
     */
    public function __construct(
        private readonly Drains $drains,
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
        private readonly LoggerInterface $logger,
        private readonly int $attempts = 3,
        ?callable $sleeper = null,
    ) {
        $this->sleeper = $sleeper === null ? null : $sleeper(...);
    }

    #[Override]
    public function write(AuditEvent ...$events): void
    {
        $byOrganization = [];
        foreach ($events as $event) {
            if ($event->organizationId !== null) {
                $byOrganization[$event->organizationId][] = $event;
            }
        }
        foreach ($byOrganization as $organizationId => $batch) {
            foreach ($this->drains->forOrganization((string) $organizationId, activeOnly: true) as $drain) {
                $accepted = array_values(array_filter($batch, static fn(AuditEvent $event): bool => $drain->accepts($event->name)));
                if ($accepted === []) {
                    continue;
                }
                try {
                    (new WebhookSink($this->client, $this->requests, $this->streams, $drain->endpoint, $drain->secret, $this->attempts, $this->sleeper))->write(...$accepted);
                    $this->drains->recordDelivery($drain->id, null);
                } catch (Throwable $exception) {
                    $this->drains->recordDelivery($drain->id, $exception->getMessage());
                    $this->logger->warning('Audit drain {drain} failed: {reason}', ['drain' => $drain->id, 'reason' => $exception->getMessage()]);
                }
            }
        }
    }
}
