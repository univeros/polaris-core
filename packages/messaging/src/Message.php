<?php

declare(strict_types=1);

namespace Polaris\Messaging;

/**
 * What a channel sends: an email (subject, text, optional HTML) or an SMS (text), addressed to one
 * recipient, with the template and variables it was rendered from so the policy and the audit can name
 * it without carrying its body.
 */
final readonly class Message
{
    public const string EMAIL = 'email';
    public const string SMS = 'sms';

    /**
     * @param array<string, mixed> $vars
     */
    public function __construct(
        public string $kind,
        public string $to,
        public string $template,
        public string $text,
        public ?string $subject = null,
        public ?string $html = null,
        public string $locale = 'en',
        public array $vars = [],
        public ?string $organizationId = null,
        public bool $essential = false,
    ) {
    }

    public function withKindAndTo(string $kind, string $to): self
    {
        return new self($kind, $to, $this->template, $this->text, $this->subject, $this->html, $this->locale, $this->vars, $this->organizationId, $this->essential);
    }
}
