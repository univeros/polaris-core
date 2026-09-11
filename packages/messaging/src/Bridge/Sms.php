<?php

declare(strict_types=1);

namespace Polaris\Messaging\Bridge;

use Override;
use Polaris\Contract\SmsSenderInterface;
use Polaris\Messaging\Message;
use Polaris\Messaging\Sender;

/**
 * Core's SMS port: core renders the code message itself, so it goes as the `sms.otp` template's text
 * through the policy and the channels.
 */
final class Sms implements SmsSenderInterface
{
    public function __construct(private readonly Sender $sender)
    {
    }

    #[Override]
    public function send(string $toE164, string $message): void
    {
        $this->sender->deliver(new Message(Message::SMS, $toE164, 'sms.otp', $message, essential: true));
    }
}
