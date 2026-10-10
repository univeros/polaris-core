<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use DateTimeImmutable;
use Polaris\Contract\DatabaseAdapter;
use Polaris\OAuth\Model\Consent;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function array_filter;
use function array_unique;
use function array_values;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * The users' consents: one row per user and client, the scopes granted so far; a request within them
 * needs no screen, a wider one asks again for the whole set.
 */
final class Consents
{
    public function __construct(private readonly DatabaseAdapter $database, private readonly ClockInterface $clock)
    {
    }

    public function find(string $userId, string $clientId): ?Consent
    {
        $row = $this->database->findOne(Schema::CONSENTS, ['user_id' => $userId, 'client_id' => $clientId]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * @param list<string> $scopes
     */
    public function covers(string $userId, string $clientId, array $scopes): bool
    {
        $consent = $this->find($userId, $clientId);
        if ($consent === null) {
            return false;
        }
        foreach ($scopes as $scope) {
            if (!in_array($scope, $consent->scopes, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param list<string> $scopes
     */
    public function grant(string $userId, string $clientId, ?string $organizationId, array $scopes): Consent
    {
        $now = $this->clock->now();
        $consent = $this->find($userId, $clientId);
        if ($consent === null) {
            $consent = new Consent();
            $consent->id = Uuid::v7()->toRfc4122();
            $consent->userId = $userId;
            $consent->clientId = $clientId;
            $consent->organizationId = $organizationId;
            $consent->scopes = array_values(array_unique($scopes));
            $consent->grantedAt = $now;
            $consent->updatedAt = $now;
            $this->database->insert(Schema::CONSENTS, [
                'id' => $consent->id,
                'user_id' => $userId,
                'client_id' => $clientId,
                'organization_id' => $organizationId,
                'scopes' => json_encode($consent->scopes, JSON_THROW_ON_ERROR),
                'granted_at' => $now,
                'updated_at' => $now,
            ]);

            return $consent;
        }
        $consent->scopes = array_values(array_unique([...$consent->scopes, ...$scopes]));
        $consent->organizationId = $organizationId ?? $consent->organizationId;
        $consent->updatedAt = $now;
        $this->database->update(Schema::CONSENTS, ['id' => $consent->id], ['scopes' => json_encode($consent->scopes, JSON_THROW_ON_ERROR), 'organization_id' => $consent->organizationId, 'updated_at' => $now]);

        return $consent;
    }

    /**
     * @return list<Consent>
     */
    public function forUser(string $userId): array
    {
        $consents = [];
        foreach ($this->database->findMany(Schema::CONSENTS, ['user_id' => $userId], ['id' => 'asc']) as $row) {
            $consents[] = self::hydrate($row);
        }

        return $consents;
    }

    public function revoke(string $userId, string $clientId): bool
    {
        return $this->database->delete(Schema::CONSENTS, ['user_id' => $userId, 'client_id' => $clientId]) > 0;
    }

    public function deleteForUser(string $userId): void
    {
        $this->database->delete(Schema::CONSENTS, ['user_id' => $userId]);
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Consent
    {
        $consent = new Consent();
        $consent->id = (string) $row['id'];
        $consent->userId = (string) $row['user_id'];
        $consent->clientId = (string) $row['client_id'];
        $consent->organizationId = is_string($row['organization_id'] ?? null) && $row['organization_id'] !== '' ? $row['organization_id'] : null;
        $scopes = is_string($row['scopes'] ?? null) ? json_decode($row['scopes'], true) : $row['scopes'];
        $consent->scopes = is_array($scopes) ? array_values(array_filter($scopes, is_string(...))) : [];
        $consent->grantedAt = $row['granted_at'] instanceof DateTimeImmutable ? $row['granted_at'] : new DateTimeImmutable((string) $row['granted_at']);
        $consent->updatedAt = $row['updated_at'] instanceof DateTimeImmutable ? $row['updated_at'] : new DateTimeImmutable((string) $row['updated_at']);

        return $consent;
    }
}
