<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Model;

use DateTimeImmutable;

use function array_filter;
use function array_values;
use function is_array;
use function is_string;
use function json_decode;

use const DATE_ATOM;

/**
 * A decision where a signal spoke (`polaris_sentinel_decision`), for the operators' review and tuning.
 */
final class DecisionRecord
{
    public string $id = '';
    public string $kind = '';
    public ?string $email = null;
    public ?string $ip = null;
    public int $score = 0;
    public string $action = 'allow';
    public bool $enforced = false;
    /** JSON lists as stored; see {@see signals()} and {@see reasons()}. */
    public string $signals = '[]';
    public string $reasons = '[]';
    public DateTimeImmutable $createdAt;

    /**
     * @return list<string>
     */
    public function signals(): array
    {
        return self::strings($this->signals);
    }

    /**
     * @return list<string>
     */
    public function reasons(): array
    {
        return self::strings($this->reasons);
    }

    /**
     * @return list<string>
     */
    private static function strings(string $json): array
    {
        $decoded = json_decode($json, true);

        return is_array($decoded) ? array_values(array_filter($decoded, is_string(...))) : [];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'kind' => $this->kind,
            'email' => $this->email,
            'ip' => $this->ip,
            'score' => $this->score,
            'action' => $this->action,
            'enforced' => $this->enforced,
            'signals' => $this->signals(),
            'reasons' => $this->reasons(),
            'created_at' => $this->createdAt->format(DATE_ATOM),
        ];
    }
}
