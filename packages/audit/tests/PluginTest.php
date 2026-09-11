<?php

declare(strict_types=1);

namespace Polaris\Audit\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Audit\Activity\ActivityTracker;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Audit\Console\PruneCommand;
use Polaris\Audit\Console\VerifyCommand;
use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Recorder;
use Polaris\Audit\Schema;
use Polaris\Audit\Store;
use Polaris\Audit\Tests\Support\SpySink;
use Polaris\Cli\Application;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Event\TokenRefreshed;
use Polaris\Event\UserLoggedIn;
use Polaris\Event\UserRegistered;
use Polaris\Polaris;
use Polaris\Schema\Schema as CoreSchema;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Audit\Tests\Support\MutableClock;
use Polaris\Tests\Support\TestKeys;
use Polaris\Wiring\Config;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The plugin wired through `Polaris::create()`: its tables, routes, services, listeners and commands.
 * Separate processes: the schema registry is static.
 */
#[CoversClass(AuditPlugin::class)]
#[CoversClass(ActivityTracker::class)]
#[CoversClass(PruneCommand::class)]
#[CoversClass(VerifyCommand::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $spy = new SpySink();
        $clock = new MutableClock(new DateTimeImmutable('2026-09-11T10:00:00+00:00'));
        $plugin = new AuditPlugin(retention: ['default' => 'P30D'], hashChain: true, sinks: [$spy], names: ['billing.invoice_paid' => 'An invoice was paid'], activityInterval: 60);
        $polaris = self::polaris($plugin, $clock);
        $graph = $polaris->graph();

        self::assertSame($plugin, AuditPlugin::of($graph));
        self::assertCount(18, $polaris->schema());
        self::assertSame(Schema::EVENTS, CoreSchema::for(AuditEvent::class)->table);
        self::assertNotNull($polaris->manifest()->find('GET', '/audit/me'));
        self::assertNotNull($polaris->manifest()->find('GET', '/audit/organization/{id}'));
        self::assertNotNull($polaris->manifest()->find('GET', '/audit/types'));
        self::assertTrue($graph->get(Catalog::class)->has('billing.invoice_paid'));
        self::assertCount(5, $polaris->listeners(), 'core\'s three, the recorder, the activity tracker');

        foreach ($polaris->listeners() as $listener) {
            $listener(new UserRegistered('u1', 'ada@example.com', 'tok'));
            $listener(new UserLoggedIn('u1', 's1', '203.0.113.7', 'UA'));
        }
        self::assertSame([Catalog::USER_SIGNED_UP, Catalog::SESSION_SIGNED_IN], array_map(static fn(AuditEvent $e): string => $e->name, $spy->events));
        $stored = $graph->get(Store::class)->read(new AuditQuery());
        self::assertCount(2, $stored->events);
        self::assertNotNull($stored->events[0]->hash, 'the chain is on');
        $tracker = $graph->get(ActivityTracker::class);
        self::assertSame('2026-09-11T10:00:00+00:00', self::at($tracker, 'u1'));

        $clock->advance('+30 seconds');
        foreach ($polaris->listeners() as $listener) {
            $listener(new TokenRefreshed('u1', 'f1'));
        }
        self::assertSame('2026-09-11T10:00:00+00:00', self::at($tracker, 'u1'), 'debounced inside the interval');
    }

    private static function at(ActivityTracker $tracker, string $userId): ?string
    {
        return $tracker->lastActiveAt($userId)?->format(DATE_ATOM);
    }

    public function testTheCommandsRunOnTheApplicationsGraph(): void
    {
        $polaris = self::polaris(new AuditPlugin(hashChain: true), new MutableClock(new DateTimeImmutable('2026-09-11T10:00:00+00:00')));
        $app = new Application($polaris);
        $app->setAutoExit(false);
        $graph = $polaris->graph();
        $graph->get(Recorder::class)->record(AuditEvent::of(Catalog::USER_SIGNED_UP, new DateTimeImmutable('2025-01-01T00:00:00+00:00'), 'u1', AuditEvent::ACTOR_USER, 'u1'));
        $graph->get(Recorder::class)->record(AuditEvent::of(Catalog::SESSION_SIGNED_IN, new DateTimeImmutable('2026-09-10T00:00:00+00:00'), 'u1', AuditEvent::ACTOR_USER, 'u1'));

        $verify = new CommandTester($app->find('audit:verify'));
        self::assertSame(0, $verify->execute([]));
        self::assertStringContainsString('Chain intact: 2 event(s)', $verify->getDisplay());

        $prune = new CommandTester($app->find('audit:prune'));
        self::assertSame(0, $prune->execute([]));
        self::assertStringContainsString('Pruned 1 audit event(s)', $prune->getDisplay());
        self::assertSame(0, $verify->execute([]));
        self::assertStringContainsString('Chain intact: 2 event(s)', $verify->getDisplay(), 'the kept row and the checkpoint');
    }

    private static function polaris(AuditPlugin $plugin, MutableClock $clock): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: $clock,
            plugins: [$plugin],
        ));
    }
}
