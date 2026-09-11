<?php

declare(strict_types=1);

namespace Polaris\Audit\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Audit\Catalog;
use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Query\Page;
use Polaris\Audit\Retention\Pruner;
use Polaris\Audit\Retention\RetentionPolicy;
use Polaris\Audit\Retention\Verifier;
use Polaris\Audit\Store;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\FrozenClock;

use function implode;
use function iterator_to_array;

#[CoversClass(Store::class)]
#[CoversClass(AuditQuery::class)]
#[CoversClass(Page::class)]
#[CoversClass(Pruner::class)]
#[CoversClass(RetentionPolicy::class)]
#[CoversClass(Verifier::class)]
final class StoreTest extends TestCase
{
    private InMemoryAdapter $database;
    private Store $store;

    protected function setUp(): void
    {
        $this->database = new InMemoryAdapter();
        $this->store = new Store($this->database);
    }

    public function testWritesAndReadsNewestFirstWithFiltersAndCursor(): void
    {
        $base = new DateTimeImmutable('2026-09-11T10:00:00+00:00');
        for ($i = 0; $i < 5; ++$i) {
            $this->store->write(AuditEvent::of($i % 2 === 0 ? Catalog::SESSION_SIGNED_IN : Catalog::USER_EMAIL_VERIFIED, $base->modify("+$i minutes"), 'u1', AuditEvent::ACTOR_USER, 'u1', $i === 4 ? 'org1' : null));
        }
        $this->store->write(AuditEvent::of(Catalog::USER_DISABLED, $base->modify('+10 minutes'), 'admin1', AuditEvent::ACTOR_USER, 'u1'));

        $all = $this->store->read(new AuditQuery());
        self::assertCount(6, $all->events);
        self::assertSame(Catalog::USER_DISABLED, $all->events[0]->name, 'newest first');
        self::assertNull($all->nextCursor);

        $page = $this->store->read(new AuditQuery(limit: 2));
        self::assertCount(2, $page->events);
        self::assertSame($page->events[1]->id, $page->nextCursor);
        $next = $this->store->read(new AuditQuery(limit: 2, cursor: $page->nextCursor));
        self::assertCount(2, $next->events);
        self::assertTrue($next->events[0]->id < $page->events[1]->id);

        self::assertCount(3, $this->store->read(new AuditQuery(names: [Catalog::SESSION_SIGNED_IN]))->events);
        self::assertCount(1, $this->store->read(new AuditQuery(organizationId: 'org1'))->events);
        self::assertCount(1, $this->store->read(new AuditQuery(actorId: 'admin1'))->events);
        self::assertCount(6, $this->store->read(new AuditQuery(principalId: 'u1'))->events, 'actor or subject');
        self::assertCount(2, $this->store->read(new AuditQuery(from: $base->modify('+3 minutes'), to: $base->modify('+5 minutes')))->events);
        self::assertSame(AuditQuery::MAX_LIMIT, (new AuditQuery(limit: 10000))->limit);
        self::assertSame(['data', 'next_cursor'], array_keys($all->toArray()));
        self::assertSame('u1', $all->toArray()['data'][0]['subject_id']);
    }

    public function testTheHashChainLinksRowsAndVerifiesTamperingAndPruning(): void
    {
        $store = new Store($this->database, hashChain: true);
        $clock = new FrozenClock(new DateTimeImmutable('2026-09-11T10:00:00+00:00'));
        $catalog = new Catalog();
        $store->write(AuditEvent::of(Catalog::USER_SIGNED_UP, new DateTimeImmutable('2026-01-01T00:00:00+00:00'), 'u1', AuditEvent::ACTOR_USER, 'u1'));
        $store->write(AuditEvent::of(Catalog::SESSION_SIGNED_IN, new DateTimeImmutable('2026-01-02T00:00:00+00:00'), 'u1', AuditEvent::ACTOR_USER, 'u1'));
        $store->write(AuditEvent::of(Catalog::SESSION_SIGNED_IN, new DateTimeImmutable('2026-09-10T00:00:00+00:00'), 'u1', AuditEvent::ACTOR_USER, 'u1'));
        $chain = iterator_to_array($store->walk(), false);
        self::assertCount(3, $chain);
        self::assertNull($chain[0]->prevHash);
        self::assertNotNull($chain[0]->hash);
        self::assertSame($chain[0]->hash, $chain[1]->prevHash);
        self::assertSame($chain[1]->hash, $chain[2]->prevHash);
        self::assertSame(['rows' => 3, 'breaks' => []], (new Verifier($store))->verify());

        $pruned = (new Pruner($store, $catalog, RetentionPolicy::fromArray(['default' => 'P90D', 'names' => [Catalog::USER_SIGNED_UP => 'P7Y']]), $clock, hashChain: true))->prune();
        self::assertSame(1, $pruned, 'the January sign-in went, the sign-up is kept seven years, the September sign-in is inside 90 days');
        $report = (new Verifier($store))->verify();
        self::assertSame(3, $report['rows'], 'two kept rows plus the checkpoint');
        self::assertSame([], $report['breaks']);
        self::assertSame(Catalog::AUDIT_PRUNED, $store->read(new AuditQuery(limit: 1))->events[0]->name);

        $this->database->update('polaris_audit_event', ['name' => Catalog::USER_SIGNED_UP], ['actor_id' => 'mallory']);
        $report = (new Verifier($store))->verify();
        self::assertCount(1, $report['breaks']);
        self::assertStringContainsString('was altered', implode(' ', $report['breaks']));
    }

    public function testRetentionPolicyValidatesDurations(): void
    {
        $policy = RetentionPolicy::fromArray([]);
        self::assertSame('2026-06-13T10:00:00+00:00', $policy->keepUntil(Catalog::SESSION_SIGNED_IN, new DateTimeImmutable('2026-09-11T10:00:00+00:00'))->format(DATE_ATOM));
        $this->expectException(\InvalidArgumentException::class);
        RetentionPolicy::fromArray(['default' => 'ninety days']);
    }
}
