<?php

declare(strict_types=1);

namespace Polaris\Passkey;

use DateTimeImmutable;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Passkey\Model\Passkey;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function array_values;
use function array_filter;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * The passkeys: by user, by credential id (what an assertion names) and by the core factor they back.
 */
final class Passkeys
{
    public function __construct(private readonly DatabaseAdapter $database, private readonly ClockInterface $clock)
    {
    }

    public function create(string $userId, Attested $attested, string $name, ?string $factorId): Passkey
    {
        $passkey = new Passkey();
        $passkey->id = Uuid::v7()->toRfc4122();
        $passkey->userId = $userId;
        $passkey->credentialId = $attested->credentialId;
        $passkey->publicKey = $attested->publicKey;
        $passkey->counter = $attested->counter;
        $passkey->aaguid = $attested->aaguid;
        $passkey->transports = $attested->transports;
        $passkey->backupEligible = $attested->backupEligible;
        $passkey->backedUp = $attested->backedUp;
        $passkey->name = $name;
        $passkey->factorId = $factorId;
        $passkey->createdAt = $this->clock->now();
        $this->database->insert(Schema::PASSKEYS, [
            'id' => $passkey->id,
            'user_id' => $userId,
            'credential_id' => $passkey->credentialId,
            'public_key' => $passkey->publicKey,
            'counter' => $passkey->counter,
            'aaguid' => $passkey->aaguid,
            'transports' => json_encode($passkey->transports, JSON_THROW_ON_ERROR),
            'backup_eligible' => $passkey->backupEligible,
            'backed_up' => $passkey->backedUp,
            'name' => $name,
            'factor_id' => $factorId,
            'last_used_at' => null,
            'created_at' => $passkey->createdAt,
        ]);

        return $passkey;
    }

    public function find(string $id): ?Passkey
    {
        $row = $this->database->findOne(Schema::PASSKEYS, ['id' => $id]);

        return $row === null ? null : self::hydrate($row);
    }

    public function byCredentialId(string $credentialId): ?Passkey
    {
        $row = $this->database->findOne(Schema::PASSKEYS, ['credential_id' => $credentialId]);

        return $row === null ? null : self::hydrate($row);
    }

    public function byFactor(string $factorId): ?Passkey
    {
        $row = $this->database->findOne(Schema::PASSKEYS, ['factor_id' => $factorId]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * @return list<Passkey>
     */
    public function forUser(string $userId): array
    {
        $passkeys = [];
        foreach ($this->database->findMany(Schema::PASSKEYS, ['user_id' => $userId], ['id' => 'asc']) as $row) {
            $passkeys[] = self::hydrate($row);
        }

        return $passkeys;
    }

    /**
     * Records a use: the new counter and backup state, the time.
     */
    public function used(Passkey $passkey, Asserted $asserted): void
    {
        $this->database->update(Schema::PASSKEYS, ['id' => $passkey->id], ['counter' => $asserted->counter, 'backed_up' => $asserted->backedUp, 'last_used_at' => $this->clock->now()]);
    }

    public function rename(Passkey $passkey, string $name): void
    {
        $this->database->update(Schema::PASSKEYS, ['id' => $passkey->id], ['name' => $name]);
    }

    public function delete(Passkey $passkey): void
    {
        $this->database->delete(Schema::PASSKEYS, ['id' => $passkey->id]);
    }

    public function deleteForUser(string $userId): void
    {
        $this->database->delete(Schema::PASSKEYS, ['user_id' => $userId]);
    }

    /**
     * The passkey stays a sign-in credential when its core factor is removed.
     */
    public function detachFactor(string $factorId): void
    {
        $this->database->update(Schema::PASSKEYS, ['factor_id' => $factorId], ['factor_id' => null]);
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Passkey
    {
        $passkey = new Passkey();
        $passkey->id = (string) $row['id'];
        $passkey->userId = (string) $row['user_id'];
        $passkey->credentialId = (string) $row['credential_id'];
        $passkey->publicKey = (string) $row['public_key'];
        $passkey->counter = (int) ($row['counter'] ?? 0);
        $passkey->aaguid = (string) $row['aaguid'];
        $transports = $row['transports'] ?? null;
        $transports = is_string($transports) ? json_decode($transports, true) : $transports;
        $passkey->transports = is_array($transports) ? array_values(array_filter($transports, 'is_string')) : [];
        $passkey->backupEligible = (bool) ($row['backup_eligible'] ?? false);
        $passkey->backedUp = (bool) ($row['backed_up'] ?? false);
        $passkey->name = (string) $row['name'];
        $passkey->factorId = is_string($row['factor_id'] ?? null) && $row['factor_id'] !== '' ? $row['factor_id'] : null;
        $passkey->lastUsedAt = ($row['last_used_at'] ?? null) === null ? null : self::datetime($row['last_used_at']);
        $passkey->createdAt = self::datetime($row['created_at']);

        return $passkey;
    }

    private static function datetime(mixed $value): DateTimeImmutable
    {
        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}
