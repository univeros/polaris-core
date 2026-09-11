<?php

declare(strict_types=1);

namespace Polaris\Audit;

use function is_array;
use function preg_match;

/**
 * Strips what must never be persisted from an event's data: any key matching the secret pattern
 * (password, secret, token, code, otp, key material) at any depth, and any value marked
 * {@see Sensitive}. Redacted entries are replaced by `[redacted]`, so the shape of the data stays
 * readable and a test can assert the redaction happened.
 */
final class Redactor
{
    public const string REDACTED = '[redacted]';
    private const string PATTERN = '/password|secret|token|code|otp|private_key|credential/i';

    /**
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    public function redact(array $data): array
    {
        $clean = [];
        foreach ($data as $key => $value) {
            if ($value instanceof Sensitive || preg_match(self::PATTERN, (string) $key) === 1) {
                $clean[$key] = self::REDACTED;
                continue;
            }
            $clean[$key] = is_array($value) ? $this->redact($value) : $value;
        }

        return $clean;
    }
}
