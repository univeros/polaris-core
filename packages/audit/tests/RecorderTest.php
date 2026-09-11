<?php

declare(strict_types=1);

namespace Polaris\Audit\Tests;

use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Audit\Auditable;
use Polaris\Audit\Catalog;
use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Recorder;
use Polaris\Audit\Redactor;
use Polaris\Audit\Tests\Support\SpySink;
use Polaris\Event\MemberInvited;
use Polaris\Event\UserDisabled;
use Polaris\Event\UserLoggedIn;
use Polaris\Event\UserRegistered;
use Polaris\Tests\Support\FrozenClock;
use Psr\Clock\ClockInterface;

#[CoversClass(Recorder::class)]
#[CoversClass(AuditEvent::class)]
final class RecorderTest extends TestCase
{
    private SpySink $sink;
    private Recorder $recorder;

    protected function setUp(): void
    {
        $this->sink = new SpySink();
        $this->recorder = new Recorder(new Catalog(), new Redactor(), $this->sink, new FrozenClock(new DateTimeImmutable('2026-09-11T10:00:00+00:00')));
    }

    public function testCoreEventsBecomeCataloguedEventsWithActorSubjectAndContext(): void
    {
        ($this->recorder)(new UserRegistered('u1', 'ada@example.com', 'verification-token'));
        ($this->recorder)(new UserLoggedIn('u1', 's1', '203.0.113.7', 'Mozilla/5.0', ['pwd', 'otp']));
        ($this->recorder)(new UserDisabled('u1', 'admin1'));
        ($this->recorder)(new MemberInvited('org1', 'newhire@example.test', 'owner1', 'invite-token'));
        ($this->recorder)(new \stdClass());

        self::assertCount(4, $this->sink->events);
        [$signedUp, $signedIn, $disabled, $invited] = $this->sink->events;
        self::assertSame(Catalog::USER_SIGNED_UP, $signedUp->name);
        self::assertSame(['u1', 'user', 'u1', ['email' => 'ada@example.com']], [$signedUp->actorId, $signedUp->actorType, $signedUp->subjectId, $signedUp->data]);
        self::assertSame('2026-09-11T10:00:00+00:00', $signedUp->occurredAt->format(DATE_ATOM));
        self::assertSame(Catalog::SESSION_SIGNED_IN, $signedIn->name);
        self::assertSame(['s1', '203.0.113.7', 'Mozilla/5.0', ['amr' => ['pwd', 'otp']]], [$signedIn->sessionId, $signedIn->ip, $signedIn->userAgent, $signedIn->data]);
        self::assertSame(Catalog::USER_DISABLED, $disabled->name);
        self::assertSame(['admin1', 'u1'], [$disabled->actorId, $disabled->subjectId]);
        self::assertSame(Catalog::ORG_MEMBER_INVITED, $invited->name);
        self::assertSame(['owner1', 'org1', ['email' => 'newhire@example.test']], [$invited->actorId, $invited->organizationId, $invited->data]);
    }

    public function testAnAuditableEventOfAnotherPackageIsRecordedAsItDescribesItselfAndRedacted(): void
    {
        $catalog = new Catalog();
        $catalog->extend(['billing.invoice_paid' => 'An invoice was paid']);
        $recorder = new Recorder($catalog, new Redactor(), $this->sink, new FrozenClock(new DateTimeImmutable('2026-09-11T10:00:00+00:00')));
        $event = new class implements Auditable {
            public function toAuditEvent(ClockInterface $clock): AuditEvent
            {
                return AuditEvent::of('billing.invoice_paid', $clock->now(), 'u1', AuditEvent::ACTOR_USER, 'u1', 'org1', data: ['invoice' => 'inv-1', 'card_token' => 'tok_x']);
            }
        };

        $recorder($event);

        self::assertSame('billing.invoice_paid', $this->sink->events[0]->name);
        self::assertSame(['invoice' => 'inv-1', 'card_token' => Redactor::REDACTED], $this->sink->events[0]->data);
    }

    public function testAnUnknownNameIsRejectedBeforeAnySinkSeesIt(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->recorder->record(AuditEvent::of('nope.nothing', new DateTimeImmutable()));
        self::assertSame([], $this->sink->events);
    }
}
