<?php

declare(strict_types=1);

namespace Polaris\Passkey\Model;

use DateTimeImmutable;

use const DATE_ATOM;

/**
 * A passkey (`polaris_passkey`): the credential id and COSE public key as the authenticator presents
 * them (base64url), the signature counter, the backup flags, and the core MFA factor it backs when the
 * plugin enrols passkeys as factors.
 */
final class Passkey
{
    public string $id = '';
    public string $userId = '';
    public string $credentialId = '';
    public string $publicKey = '';
    public int $counter = 0;
    public string $aaguid = '';
    /** @var list<string> */
    public array $transports = [];
    public bool $backupEligible = false;
    public bool $backedUp = false;
    public string $name = '';
    public ?string $factorId = null;
    public ?DateTimeImmutable $lastUsedAt = null;
    public DateTimeImmutable $createdAt;

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'aaguid' => $this->aaguid,
            'transports' => $this->transports,
            'backed_up' => $this->backedUp,
            'factor_id' => $this->factorId,
            'last_used_at' => $this->lastUsedAt?->format(DATE_ATOM),
            'created_at' => $this->createdAt->format(DATE_ATOM),
        ];
    }
}
