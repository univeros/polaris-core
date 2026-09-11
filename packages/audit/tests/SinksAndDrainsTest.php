<?php

declare(strict_types=1);

namespace Polaris\Audit\Tests;

use DateTimeImmutable;
use HttpSoft\Message\RequestFactory;
use HttpSoft\Message\StreamFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Audit\Catalog;
use Polaris\Audit\Drain\Drains;
use Polaris\Audit\Drain\DrainSink;
use Polaris\Audit\Model\AuditDrain;
use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Sink\FileSink;
use Polaris\Audit\Sink\Psr3Sink;
use Polaris\Audit\Sink\SinkChain;
use Polaris\Audit\Sink\WebhookSink;
use Polaris\Audit\Tests\Support\FakeHttpClient;
use Polaris\Audit\Tests\Support\SpySink;
use Polaris\Security\SodiumEncrypter;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\FrozenClock;
use Polaris\Tests\Support\RecordingLogger;
use RuntimeException;

#[CoversClass(SinkChain::class)]
#[CoversClass(Psr3Sink::class)]
#[CoversClass(FileSink::class)]
#[CoversClass(WebhookSink::class)]
#[CoversClass(Drains::class)]
#[CoversClass(DrainSink::class)]
#[CoversClass(AuditDrain::class)]
final class SinksAndDrainsTest extends TestCase
{
    public function testTheChainIsFailOpenAndTheSimpleSinksWrite(): void
    {
        $logger = new RecordingLogger();
        $spy = new SpySink();
        $file = sys_get_temp_dir() . '/polaris-audit-' . uniqid() . '.jsonl';
        $failing = new class implements \Polaris\Audit\Sink\AuditSink {
            public function write(AuditEvent ...$events): void
            {
                throw new RuntimeException('down');
            }
        };
        $chain = new SinkChain($logger, $failing, new Psr3Sink($logger), new FileSink($file), $spy);

        $chain->write(self::event('u1'));

        self::assertCount(1, $spy->events, 'the sink after the failing one still ran');
        self::assertCount(1, array_filter($logger->records, static fn(array $r): bool => $r['level'] === 'error' && str_contains($r['message'], 'Audit sink')));
        self::assertCount(1, array_filter($logger->records, static fn(array $r): bool => $r['level'] === 'info' && $r['message'] === 'audit {name}'));
        self::assertSame(Catalog::SESSION_SIGNED_IN, json_decode((string) file_get_contents($file), true)['name']);
        unlink($file);
    }

    public function testTheWebhookSignsRetriesAndGivesUp(): void
    {
        $client = new FakeHttpClient([0, 503, 200]);
        $pauses = [];
        $sink = new WebhookSink($client, new RequestFactory(), new StreamFactory(), 'https://hooks.example.test/audit', 's3cret', 3, static function (int $ms) use (&$pauses): void {
            $pauses[] = $ms;
        });

        $sink->write(self::event('u1'), self::event('u2'));

        self::assertCount(3, $client->requests, 'a transport failure and a 503 were retried');
        self::assertSame([200, 400], $pauses);
        $request = $client->requests[2];
        $body = (string) $request->getBody();
        self::assertSame('sha256=' . hash_hmac('sha256', $body, 's3cret'), $request->getHeaderLine(WebhookSink::SIGNATURE_HEADER));
        self::assertNotSame('', $request->getHeaderLine(WebhookSink::DELIVERY_HEADER));
        self::assertCount(2, json_decode($body, true)['events']);

        $client = new FakeHttpClient([400]);
        $sink = new WebhookSink($client, new RequestFactory(), new StreamFactory(), 'https://hooks.example.test/audit', 's3cret', 3, static fn(int $ms) => null);
        try {
            $sink->write(self::event('u1'));
            self::fail('a 4xx is final');
        } catch (RuntimeException $exception) {
            self::assertCount(1, $client->requests, 'not retried');
            self::assertStringContainsString('HTTP 400', $exception->getMessage());
        }
    }

    public function testDrainsDeliverAnOrganizationsMatchingEventsAndRecordTheOutcome(): void
    {
        $database = new InMemoryAdapter();
        $clock = new FrozenClock(new DateTimeImmutable('2026-09-11T10:00:00+00:00'));
        $encrypter = new SodiumEncrypter(str_repeat('k', 32));
        $drains = new Drains($database, $encrypter, $clock);
        $webhook = $drains->create('org1', 'https://acme.example.test/audit', 'drain-secret', ['org.*', Catalog::SESSION_SIGNED_IN], 'owner1');
        $paused = $drains->create('org1', 'https://paused.example.test', 'x');
        $drains->setStatus($paused->id, AuditDrain::STATUS_PAUSED);
        $drains->create('org2', 'https://other.example.test', 'y');
        self::assertNotSame('drain-secret', $database->findOne('polaris_audit_drain', ['id' => $webhook->id])['secret'], 'encrypted at rest');
        $found = $drains->find($webhook->id);
        self::assertNotNull($found);
        self::assertSame('drain-secret', $found->secret);
        self::assertCount(2, $drains->forOrganization('org1'));
        self::assertCount(1, $drains->forOrganization('org1', activeOnly: true));
        self::assertArrayNotHasKey('secret', $webhook->toArray());

        $client = new FakeHttpClient([200]);
        $logger = new RecordingLogger();
        $sink = new DrainSink($drains, $client, new RequestFactory(), new StreamFactory(), $logger, 1, static fn(int $ms) => null);
        $signedIn = self::event('u1');
        $signedIn->organizationId = 'org1';
        $invited = AuditEvent::of(Catalog::ORG_MEMBER_INVITED, $clock->now(), 'owner1', AuditEvent::ACTOR_USER, null, 'org1');
        $verified = AuditEvent::of(Catalog::USER_EMAIL_VERIFIED, $clock->now(), 'u1', AuditEvent::ACTOR_USER, 'u1', 'org1');
        $noOrg = self::event('u3');

        $sink->write($signedIn, $invited, $verified, $noOrg);

        self::assertCount(1, $client->requests, 'one delivery to the active drain, the paused and the other organization untouched');
        self::assertSame('https://acme.example.test/audit', (string) $client->requests[0]->getUri());
        $delivered = json_decode((string) $client->requests[0]->getBody(), true)['events'];
        self::assertSame([Catalog::SESSION_SIGNED_IN, Catalog::ORG_MEMBER_INVITED], array_column($delivered, 'name'), 'the filter kept two of three');
        $after = $drains->find($webhook->id);
        self::assertNotNull($after);
        self::assertNotNull($after->lastDeliveryAt);
        self::assertNull($after->lastError);

        $failing = new DrainSink($drains, new FakeHttpClient([500]), new RequestFactory(), new StreamFactory(), $logger, 1, static fn(int $ms) => null);
        $failing->write($signedIn);
        $failed = $drains->find($webhook->id);
        self::assertNotNull($failed);
        self::assertStringContainsString('HTTP 500', (string) $failed->lastError);
        self::assertTrue($drains->delete($webhook->id));
        self::assertNull($drains->find($webhook->id));
    }

    private static function event(string $userId): AuditEvent
    {
        return AuditEvent::of(Catalog::SESSION_SIGNED_IN, new DateTimeImmutable('2026-09-11T10:00:00+00:00'), $userId, AuditEvent::ACTOR_USER, $userId, null, 's1', '203.0.113.7', 'UA', ['amr' => ['pwd']]);
    }
}
