<?php

declare(strict_types=1);

namespace Polaris\Messaging\Template;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Messaging\Model\Template;
use Polaris\Messaging\Schema;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function is_string;

/**
 * The overrides: the instance's from the plugin's configuration, an organization's from
 * `polaris_messaging_template` (its branding), each a subject, a text and an optional HTML with
 * `{placeholders}`.
 */
final class Templates
{
    public const array KEYS = [
        'email.verify', 'email.reset_password', 'email.magic_link', 'email.otp', 'email.invite', 'email.new_device',
        'email.password_changed', 'email.account_locked', 'email.mfa_enrolled', 'email.mfa_factor_removed',
        'email.recovery_codes_regenerated', 'email.recovery_code_used', 'sms.otp', 'sms.new_device',
    ];

    /**
     * @param array<string, array<string, array{subject?: string, text: string, html?: string}>> $instance locale => key => parts
     */
    public function __construct(private readonly DatabaseAdapter $database, private readonly ClockInterface $clock, private readonly array $instance = [])
    {
    }

    /**
     * @return array{subject?: string, text: string, html?: string}|null
     */
    public function override(string $key, string $locale, ?string $organizationId): ?array
    {
        if ($organizationId !== null) {
            $row = $this->database->findOne(Schema::TEMPLATES, ['organization_id' => $organizationId, 'key' => $key, 'locale' => $locale]);
            if ($row !== null) {
                $parts = ['text' => (string) $row['text']];
                if (is_string($row['subject'] ?? null) && $row['subject'] !== '') {
                    $parts['subject'] = $row['subject'];
                }
                if (is_string($row['html'] ?? null) && $row['html'] !== '') {
                    $parts['html'] = $row['html'];
                }

                return $parts;
            }
        }

        return $this->instance[$locale][$key] ?? null;
    }

    /**
     * Stores (or replaces) an organization's override.
     */
    public function set(string $organizationId, string $key, string $locale, string $text, ?string $subject = null, ?string $html = null): Template
    {
        $template = new Template();
        $template->id = Uuid::v7()->toRfc4122();
        $template->organizationId = $organizationId;
        $template->key = $key;
        $template->locale = $locale;
        $template->subject = $subject;
        $template->text = $text;
        $template->html = $html;
        $template->updatedAt = $this->clock->now();
        $criteria = ['organization_id' => $organizationId, 'key' => $key, 'locale' => $locale];
        $data = ['subject' => $subject, 'text' => $text, 'html' => $html, 'updated_at' => $template->updatedAt];
        if ($this->database->update(Schema::TEMPLATES, $criteria, $data) === 0) {
            $this->database->insert(Schema::TEMPLATES, ['id' => $template->id, ...$criteria, ...$data]);
        }

        return $template;
    }

    public function remove(string $organizationId, string $key, string $locale): bool
    {
        return $this->database->delete(Schema::TEMPLATES, ['organization_id' => $organizationId, 'key' => $key, 'locale' => $locale]) > 0;
    }
}
