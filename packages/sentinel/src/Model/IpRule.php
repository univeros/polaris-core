<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Model;

use DateTimeImmutable;

use const DATE_ATOM;

/**
 * An allow or block rule for an address or a CIDR block (`polaris_sentinel_ip_rule`).
 */
final class IpRule
{
    public const string ALLOW = 'allow';
    public const string BLOCK = 'block';

    public string $id = '';
    public string $cidr = '';
    public string $action = self::BLOCK;
    public ?string $note = null;
    public ?string $createdBy = null;
    public DateTimeImmutable $createdAt;

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return ['id' => $this->id, 'cidr' => $this->cidr, 'action' => $this->action, 'note' => $this->note, 'created_by' => $this->createdBy, 'created_at' => $this->createdAt->format(DATE_ATOM)];
    }
}
