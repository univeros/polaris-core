<?php

declare(strict_types=1);

namespace Polaris\Agent\Tests;

use PHPUnit\Framework\TestCase;
use Polaris\Agent\AgentException;
use Polaris\Agent\ApprovalException;
use Polaris\Agent\Approvals;
use Polaris\Agent\Tests\Support\Fixtures;

use function array_column;

final class ApprovalsTest extends TestCase
{
    /** A fake clock the fake sleep advances. */
    private int $clock = 1000;
    /** @var list<int> */
    private array $slept = [];

    private function sleep(): callable
    {
        return function (int $seconds): void {
            $this->slept[] = $seconds;
            $this->clock += $seconds;
        };
    }

    public function testItPollsAtTheIntervalSlowsDownOnA429AndReturnsTheApprovalsGrantsOnceActive(): void
    {
        $pending = [Fixtures::grant(['id' => 'g2', 'capability' => 'org.rename', 'status' => 'pending', 'approval_id' => 'ap1']), Fixtures::grant()];
        $active = [Fixtures::grant(['id' => 'g2', 'capability' => 'org.rename', 'status' => 'active', 'approval_id' => 'ap1']), Fixtures::grant()];
        $answers = [static fn(): array => $pending, static fn(): never => throw new AgentException('429', 429), static fn(): array => $pending, static fn(): array => $active];
        $polls = 0;
        $grants = Approvals::wait(Fixtures::approval(['interval' => 5, 'expires_in' => 600]), function () use (&$polls, $answers): array {
            return $answers[$polls++]();
        }, $this->sleep(), fn(): int => $this->clock);
        self::assertSame(['g2'], array_column($grants, 'id'));
        self::assertSame([5, 5, 10, 10], $this->slept);
    }

    public function testADeniedGrantEndsTheWait(): void
    {
        $this->expectExceptionObject(new ApprovalException(ApprovalException::DENIED, Fixtures::approval(), 'The approval was denied.'));
        Approvals::wait(Fixtures::approval(), static fn(): array => [Fixtures::grant(['status' => 'denied', 'approval_id' => 'ap1'])], $this->sleep(), fn(): int => $this->clock);
    }

    public function testTheWaitExpiresWithTheApprovalAndNeverExceedsMaxAttempts(): void
    {
        $polls = 0;
        $pending = static fn(): array => [Fixtures::grant(['status' => 'pending', 'approval_id' => 'ap1'])];
        try {
            Approvals::wait(Fixtures::approval(['interval' => 5, 'expires_in' => 12]), function () use (&$polls, $pending): array {
                $polls++;

                return $pending();
            }, $this->sleep(), fn(): int => $this->clock);
            self::fail('expired');
        } catch (ApprovalException $exception) {
            self::assertSame([ApprovalException::EXPIRED, 2], [$exception->outcome, $polls]);
        }
        $polls = 0;
        try {
            Approvals::wait(Fixtures::approval(['interval' => 1, 'expires_in' => 600]), function () use (&$polls, $pending): array {
                $polls++;

                return $pending();
            }, $this->sleep(), fn(): int => $this->clock, 3);
            self::fail('bounded');
        } catch (ApprovalException $exception) {
            self::assertSame([ApprovalException::EXPIRED, 3], [$exception->outcome, $polls]);
        }
    }

    public function testACancelledWaitStopsBeforePollingAndOtherErrorsAreRethrown(): void
    {
        $polls = 0;
        try {
            Approvals::wait(Fixtures::approval(['interval' => 30]), function () use (&$polls): array {
                $polls++;

                return [];
            }, $this->sleep(), fn(): int => $this->clock, cancelled: static fn(): bool => true);
            self::fail('cancelled');
        } catch (ApprovalException $exception) {
            self::assertSame([ApprovalException::CANCELLED, 0], [$exception->outcome, $polls]);
        }
        $this->expectExceptionObject(new AgentException('gone', 401));
        Approvals::wait(Fixtures::approval(), static fn(): never => throw new AgentException('gone', 401), $this->sleep(), fn(): int => $this->clock);
    }
}
