<?php

declare(strict_types=1);

namespace Polaris\Sso;

use DateTimeImmutable;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Sso\Model\Domain;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function bin2hex;
use function random_bytes;
use function strtolower;

/**
 * The organizations' domains (`polaris_sso_domain`): claimed with a token, verified through DNS or HTTPS,
 * then routing sign-ins. A domain belongs to one organization across the instance.
 */
final class Domains
{
    public function __construct(private readonly DatabaseAdapter $database, private readonly ClockInterface $clock)
    {
    }

    public function find(string $id): ?Domain
    {
        $row = $this->database->findOne(Schema::DOMAINS, ['id' => $id]);

        return $row === null ? null : self::hydrate($row);
    }

    public function findByName(string $domain): ?Domain
    {
        $row = $this->database->findOne(Schema::DOMAINS, ['domain' => strtolower($domain)]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * The verified domain, for routing; null when unknown or unverified.
     */
    public function verified(string $domain): ?Domain
    {
        $found = $this->findByName($domain);

        return $found?->verifiedAt === null ? null : $found;
    }

    /**
     * @return list<Domain>
     */
    public function forOrganization(string $organizationId): array
    {
        $domains = [];
        foreach ($this->database->findMany(Schema::DOMAINS, ['organization_id' => $organizationId], ['id' => 'asc']) as $row) {
            $domains[] = self::hydrate($row);
        }

        return $domains;
    }

    public function add(string $organizationId, string $providerId, string $domain): Domain
    {
        $record = new Domain();
        $record->id = Uuid::v7()->toRfc4122();
        $record->organizationId = $organizationId;
        $record->providerId = $providerId;
        $record->domain = strtolower($domain);
        $record->token = 'polaris-sso-' . bin2hex(random_bytes(16));
        $record->createdAt = $this->clock->now();
        $this->database->insert(Schema::DOMAINS, [
            'id' => $record->id,
            'organization_id' => $record->organizationId,
            'provider_id' => $record->providerId,
            'domain' => $record->domain,
            'token' => $record->token,
            'verified_at' => null,
            'created_at' => $record->createdAt,
        ]);

        return $record;
    }

    public function markVerified(Domain $domain): Domain
    {
        $domain->verifiedAt = $this->clock->now();
        $this->database->update(Schema::DOMAINS, ['id' => $domain->id], ['verified_at' => $domain->verifiedAt]);

        return $domain;
    }

    public function delete(string $id): bool
    {
        return $this->database->delete(Schema::DOMAINS, ['id' => $id]) > 0;
    }

    public function deleteForProvider(string $providerId): void
    {
        $this->database->delete(Schema::DOMAINS, ['provider_id' => $providerId]);
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Domain
    {
        $domain = new Domain();
        $domain->id = (string) $row['id'];
        $domain->organizationId = (string) $row['organization_id'];
        $domain->providerId = (string) $row['provider_id'];
        $domain->domain = (string) $row['domain'];
        $domain->token = (string) $row['token'];
        $verified = $row['verified_at'] ?? null;
        $domain->verifiedAt = $verified === null || $verified === '' ? null : ($verified instanceof DateTimeImmutable ? $verified : new DateTimeImmutable((string) $verified));
        $created = $row['created_at'];
        $domain->createdAt = $created instanceof DateTimeImmutable ? $created : new DateTimeImmutable((string) $created);

        return $domain;
    }
}
