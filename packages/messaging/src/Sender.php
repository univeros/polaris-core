<?php

declare(strict_types=1);

namespace Polaris\Messaging;

use Polaris\Messaging\Template\TemplateRenderer;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;

use function hash;
use function sprintf;
use function strtolower;

/**
 * The one way out: render the template, ask the policy, hand the message to the outbox, deliver through
 * the first channel of its kind (falling back to the message's alternative when the policy has one and
 * the channel failed), record `messaging.sent`. A refused or failed send never breaks the operation
 * that asked for it: it is logged and answered as null.
 */
final class Sender
{
    /**
     * @param list<Channel> $channels
     */
    public function __construct(
        private readonly array $channels,
        private readonly TemplateRenderer $renderer,
        private readonly MessagePolicy $policy,
        private readonly Outbox $outbox,
        private readonly EventDispatcherInterface $events,
        private readonly LoggerInterface $logger,
        private readonly string $defaultLocale = 'en',
    ) {
    }

    /**
     * Renders `$template` for the recipient and sends it.
     *
     * @param array<string, mixed> $vars
     * @param array<string, string> $alternatives kind => recipient, for the policy's fallback (`['email' => $user->email]`)
     */
    public function send(string $kind, string $to, string $template, array $vars = [], ?string $locale = null, ?string $organizationId = null, bool $essential = false, array $alternatives = []): ?Receipt
    {
        $rendered = $this->renderer->render($template, $locale ?? $this->defaultLocale, $vars, $organizationId);
        $message = new Message($kind, $to, $template, $rendered->text, $rendered->subject, $rendered->html, $locale ?? $this->defaultLocale, $vars, $organizationId, $essential);

        return $this->deliver($message, $alternatives);
    }

    /**
     * @param array<string, string> $alternatives
     */
    public function deliver(Message $message, array $alternatives = []): ?Receipt
    {
        if (!$this->policy->allows($message)) {
            $this->logger->notice('[polaris messaging] {template} to {recipient} not sent: the policy refused it.', ['template' => $message->template, 'recipient' => self::hash($message->to)]);

            return null;
        }
        $receipt = null;
        $this->outbox->push($message, function (Message $message) use (&$receipt, $alternatives): void {
            $receipt = $this->attempt($message, false) ?? $this->fallback($message, $alternatives);
        });

        return $receipt;
    }

    /**
     * @param array<string, string> $alternatives
     */
    private function fallback(Message $message, array $alternatives): ?Receipt
    {
        $kind = $this->policy->fallbackFor($message->kind);
        $to = $kind === null ? null : ($alternatives[$kind] ?? null);
        if ($kind === null || $to === null) {
            return null;
        }
        $rendered = $this->renderer->render(self::sibling($message->template, $kind), $message->locale, $message->vars, $message->organizationId);

        return $this->attempt(new Message($kind, $to, self::sibling($message->template, $kind), $rendered->text, $rendered->subject, $rendered->html, $message->locale, $message->vars, $message->organizationId, $message->essential), true);
    }

    private function attempt(Message $message, bool $fallback): ?Receipt
    {
        foreach ($this->channels as $channel) {
            if (!$channel->supports($message->kind)) {
                continue;
            }
            try {
                $receipt = $channel->send($message);
            } catch (DeliveryException $exception) {
                $this->logger->warning('[polaris messaging] {channel} failed to send {template}: {reason}', ['channel' => $channel->name(), 'template' => $message->template, 'reason' => $exception->getMessage()]);
                continue;
            }
            $this->events->dispatch(new MessageSent($message->kind, $message->template, self::hash($message->to), $receipt->channel, $receipt->providerId, $message->organizationId, $fallback));

            return $receipt;
        }
        $this->logger->error('[polaris messaging] no channel delivered {template} ({kind}).', ['template' => $message->template, 'kind' => $message->kind]);

        return null;
    }

    /**
     * The same purpose on another kind: `sms.otp` → `email.otp`.
     */
    private static function sibling(string $template, string $kind): string
    {
        $dot = strpos($template, '.');

        return sprintf('%s.%s', $kind, $dot === false ? $template : substr($template, $dot + 1));
    }

    private static function hash(string $recipient): string
    {
        return hash('sha256', strtolower($recipient));
    }
}
