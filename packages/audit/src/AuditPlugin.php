<?php

declare(strict_types=1);

namespace Polaris\Audit;

use Closure;
use LogicException;
use Override;
use Polaris\Audit\Activity\ActivityTracker;
use Polaris\Audit\Console\PruneCommand;
use Polaris\Audit\Console\VerifyCommand;
use Polaris\Audit\Drain\Drains;
use Polaris\Audit\Drain\DrainSink;
use Polaris\Audit\Retention\Pruner;
use Polaris\Audit\Retention\RetentionPolicy;
use Polaris\Audit\Retention\Verifier;
use Polaris\Audit\Sink\AuditSink;
use Polaris\Audit\Sink\DatabaseSink;
use Polaris\Audit\Sink\SinkChain;
use Polaris\Cli\CommandProvider;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

use function dirname;

/**
 * The audit plugin: `new AuditPlugin(retention: [...], hashChain: true, sinks: [...])` in
 * `Config::$plugins`. Every core event becomes a catalogued, redacted event in `polaris_audit_event`
 * (the default sink), in the extra sinks, and in the organization's drains when a PSR-18 client is
 * given; `GET /audit/me`, `/audit/organization/{id}` and `/audit/types` read it; `audit:prune` and
 * `audit:verify` maintain it.
 */
final class AuditPlugin extends AbstractPlugin implements CommandProvider
{
    public const string ID = 'audit';

    private readonly RetentionPolicy $retention;
    private readonly Catalog $catalog;
    private readonly ?Closure $sleeper;

    /**
     * @param array<string, mixed> $retention `['default' => 'P90D', 'names' => ['user.deleted' => 'P7Y']]`
     * @param list<AuditSink> $sinks sinks beside the database
     * @param array<string, string> $names event names of the application (`billing.invoice_paid` => description)
     * @param callable(int): void|null $sleeper the pause between webhook attempts (tests pass a no-op)
     */
    public function __construct(
        array $retention = [],
        private readonly bool $hashChain = false,
        private readonly array $sinks = [],
        array $names = [],
        private readonly int $activityInterval = 300,
        private readonly ?ClientInterface $httpClient = null,
        private readonly ?RequestFactoryInterface $requestFactory = null,
        private readonly ?StreamFactoryInterface $streamFactory = null,
        private readonly int $webhookAttempts = 3,
        ?callable $sleeper = null,
    ) {
        $this->sleeper = $sleeper === null ? null : $sleeper(...);
        $this->retention = RetentionPolicy::fromArray($retention);
        $this->catalog = new Catalog();
        $this->catalog->extend($names);
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The audit plugin is not registered.');
        }

        return $plugin;
    }

    #[Override]
    public function id(): string
    {
        return self::ID;
    }

    #[Override]
    public function schema(): array
    {
        return Schema::models();
    }

    #[Override]
    public static function manifestDirectory(): string
    {
        return dirname(__DIR__) . '/api';
    }

    #[Override]
    public function services(): array
    {
        return [
            Catalog::class => fn(): Catalog => $this->catalog,
            Redactor::class => static fn(): Redactor => new Redactor(),
            Store::class => fn(Graph $graph): Store => new Store($graph->database(), $this->hashChain),
            Drains::class => static fn(Graph $graph): Drains => new Drains($graph->database(), $graph->encrypter(), $graph->clock()),
            AuditSink::class => fn(Graph $graph): AuditSink => $this->sinks($graph),
            Recorder::class => static fn(Graph $graph): Recorder => new Recorder($graph->get(Catalog::class), $graph->get(Redactor::class), $graph->get(AuditSink::class), $graph->clock()),
            ActivityTracker::class => fn(Graph $graph): ActivityTracker => new ActivityTracker($graph->database(), $graph->cache(), $graph->clock(), $this->activityInterval),
        ];
    }

    #[Override]
    public function listeners(Graph $graph): array
    {
        return [$graph->get(Recorder::class), $graph->get(ActivityTracker::class)];
    }

    #[Override]
    public function commands(Graph $graph): array
    {
        return [new PruneCommand(static fn(): Graph => $graph), new VerifyCommand(static fn(): Graph => $graph)];
    }

    public function catalog(): Catalog
    {
        return $this->catalog;
    }

    public function retention(): RetentionPolicy
    {
        return $this->retention;
    }

    public function hashChain(): bool
    {
        return $this->hashChain;
    }

    public function pruner(Graph $graph): Pruner
    {
        return new Pruner($graph->get(Store::class), $this->catalog, $this->retention, $graph->clock(), $this->hashChain);
    }

    public function verifier(Graph $graph): Verifier
    {
        return new Verifier($graph->get(Store::class));
    }

    private function sinks(Graph $graph): AuditSink
    {
        $sinks = [new DatabaseSink($graph->get(Store::class)), ...$this->sinks];
        if ($this->httpClient !== null && $this->requestFactory !== null && $this->streamFactory !== null) {
            $sinks[] = new DrainSink($graph->get(Drains::class), $this->httpClient, $this->requestFactory, $this->streamFactory, $graph->logger(), $this->webhookAttempts, $this->sleeper);
        }

        return new SinkChain($graph->logger(), ...$sinks);
    }
}
