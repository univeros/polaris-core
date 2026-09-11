<?php

declare(strict_types=1);

namespace Polaris\Messaging;

use Polaris\Contract\RateStore;

use function hash;
use function sprintf;
use function strtolower;

/**
 * Who may be sent what: a cap per recipient and template family (`5` in `600` seconds by default), a
 * fallback channel kind when a kind cannot deliver (SMS → email when the recipient has an address), and
 * quiet mode through a {@see Suppressor}.
 */
final class MessagePolicy
{
    /**
     * @param array<string, array{int, int}> $caps template prefix (`sms.otp`, `email`) => [limit, window seconds]; `*` is the default
     * @param array<string, string> $fallback kind => kind (`sms` => `email`)
     */
    public function __construct(
        private readonly RateStore $rates,
        private readonly array $caps = ['*' => [5, 600]],
        private readonly array $fallback = [Message::SMS => Message::EMAIL],
        private readonly ?Suppressor $suppressor = null,
    ) {
    }

    /**
     * Counts the send against the recipient's cap; false when the cap is reached.
     */
    public function allows(Message $message): bool
    {
        if (!$message->essential && $this->suppressor?->suppresses($message) === true) {
            return false;
        }
        [$limit, $window] = $this->caps[$message->template] ?? $this->caps[$message->kind] ?? $this->caps['*'] ?? [5, 600];
        $key = sprintf('polaris:messaging:%s:%s', $message->template, hash('sha256', strtolower($message->to)));

        return $this->rates->hit($key, $limit, $window)->allowed;
    }

    public function fallbackFor(string $kind): ?string
    {
        return $this->fallback[$kind] ?? null;
    }
}
