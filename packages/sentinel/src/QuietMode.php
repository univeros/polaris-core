<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use DateInterval;
use Override;
use Polaris\Messaging\Message;
use Polaris\Messaging\Suppressor;
use Psr\Clock\ClockInterface;

/**
 * Messaging's quiet mode: a recipient the sentinel challenged or blocked in the last hour gets no
 * non-essential message.
 */
final class QuietMode implements Suppressor
{
    public function __construct(private readonly Decisions $decisions, private readonly ClockInterface $clock, private readonly string $window = 'PT1H')
    {
    }

    #[Override]
    public function suppresses(Message $message): bool
    {
        if ($message->kind !== Message::EMAIL) {
            return false;
        }
        $since = $this->clock->now()->sub(new DateInterval($this->window));
        foreach ($this->decisions->list(email: $message->to, limit: 5)['data'] as $decision) {
            if ($decision['action'] !== Decision::ALLOW && new \DateTimeImmutable((string) $decision['created_at']) >= $since) {
                return true;
            }
        }

        return false;
    }
}
