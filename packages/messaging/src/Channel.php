<?php

declare(strict_types=1);

namespace Polaris\Messaging;

/**
 * A way to deliver a message: an email transport, an SMS provider, a log, an array in tests. A channel
 * that cannot deliver throws {@see DeliveryException}; the sender decides about fallbacks.
 */
interface Channel
{
    public function name(): string;

    /**
     * @param string $kind {@see Message::EMAIL} or {@see Message::SMS}
     */
    public function supports(string $kind): bool;

    /**
     * @throws DeliveryException
     */
    public function send(Message $message): Receipt;
}
