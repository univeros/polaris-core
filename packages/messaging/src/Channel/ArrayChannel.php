<?php

declare(strict_types=1);

namespace Polaris\Messaging\Channel;

use DateTimeImmutable;
use Override;
use Polaris\Messaging\Channel;
use Polaris\Messaging\DeliveryException;
use Polaris\Messaging\Message;
use Polaris\Messaging\Receipt;

use function count;

/**
 * Tests: keeps every message; can be told to fail, and to support one kind only.
 */
final class ArrayChannel implements Channel
{
    /** @var list<Message> */
    public array $messages = [];

    /**
     * @param list<string> $kinds
     */
    public function __construct(private readonly string $name = 'array', private readonly array $kinds = [Message::EMAIL, Message::SMS], public bool $failing = false)
    {
    }

    #[Override]
    public function name(): string
    {
        return $this->name;
    }

    #[Override]
    public function supports(string $kind): bool
    {
        return in_array($kind, $this->kinds, true);
    }

    #[Override]
    public function send(Message $message): Receipt
    {
        if ($this->failing) {
            throw new DeliveryException(sprintf('%s is down.', $this->name));
        }
        $this->messages[] = $message;

        return new Receipt($this->name, sprintf('%s-%d', $this->name, count($this->messages)), new DateTimeImmutable());
    }
}
