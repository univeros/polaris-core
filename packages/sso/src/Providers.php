<?php

declare(strict_types=1);

namespace Polaris\Sso;

use DateTimeImmutable;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\EncrypterInterface;
use Polaris\Sso\Model\Provider;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function array_slice;
use function count;
use function is_string;
use function json_encode;
use function max;
use function min;

use const JSON_THROW_ON_ERROR;

/**
 * The organizations' providers (`polaris_sso_provider`); the OIDC client secret is encrypted at rest
 * and decrypted only for the token exchange.
 */
final class Providers
{
    public const int DEFAULT_LIMIT = 50;
    public const int MAX_LIMIT = 200;

    public function __construct(private readonly DatabaseAdapter $database, private readonly EncrypterInterface $encrypter, private readonly ClockInterface $clock)
    {
    }

    public function find(string $id): ?Provider
    {
        $row = $this->database->findOne(Schema::PROVIDERS, ['id' => $id]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * @return list<Provider>
     */
    public function forOrganization(string $organizationId): array
    {
        $providers = [];
        foreach ($this->database->findMany(Schema::PROVIDERS, ['organization_id' => $organizationId], ['id' => 'asc']) as $row) {
            $providers[] = self::hydrate($row);
        }

        return $providers;
    }

    /**
     * Every provider, oldest first, for the operators.
     *
     * @return array{data: list<array<string, mixed>>, next_cursor: string|null}
     */
    public function list(?string $organizationId = null, ?string $cursor = null, int $limit = self::DEFAULT_LIMIT): array
    {
        $limit = max(1, min(self::MAX_LIMIT, $limit));
        $criteria = [];
        if ($organizationId !== null) {
            $criteria['organization_id'] = $organizationId;
        }
        if ($cursor !== null) {
            $criteria['id'] = Condition::gt($cursor);
        }
        $rows = $this->database->findMany(Schema::PROVIDERS, $criteria, ['id' => 'asc'], $limit + 1);
        $data = [];
        foreach (array_slice($rows, 0, $limit) as $row) {
            $data[] = self::hydrate($row)->toArray();
        }

        return ['data' => $data, 'next_cursor' => count($rows) > $limit && $data !== [] ? $data[count($data) - 1]['id'] : null];
    }

    /**
     * @param array<string, mixed> $config the secret in clear; stored encrypted
     * @param array<string, string> $attributes
     * @param array{enabled: bool, roles: list<string>} $jit
     * @param list<string> $redirectUris
     */
    public function create(string $organizationId, string $type, string $name, string $issuer, array $config, array $attributes, array $jit, array $redirectUris, bool $enabled, ?string $createdBy): Provider
    {
        $provider = new Provider();
        $provider->id = Uuid::v7()->toRfc4122();
        $provider->organizationId = $organizationId;
        $provider->type = $type;
        $provider->createdBy = $createdBy;
        $provider->createdAt = $this->clock->now();
        $this->fill($provider, $name, $issuer, $config, $attributes, $jit, $redirectUris, $enabled);
        $this->database->insert(Schema::PROVIDERS, $this->row($provider));

        return $provider;
    }

    /**
     * @param array<string, mixed> $config the secret in clear, or absent to keep the stored one
     * @param array<string, string> $attributes
     * @param array{enabled: bool, roles: list<string>} $jit
     * @param list<string> $redirectUris
     */
    public function update(Provider $provider, string $name, string $issuer, array $config, array $attributes, array $jit, array $redirectUris, bool $enabled): Provider
    {
        $current = $provider->config();
        if (!isset($config[Provider::SECRET]) && isset($current[Provider::SECRET])) {
            $config[Provider::SECRET] = $current[Provider::SECRET];
            $this->fill($provider, $name, $issuer, $config, $attributes, $jit, $redirectUris, $enabled, encryptSecret: false);
        } else {
            $this->fill($provider, $name, $issuer, $config, $attributes, $jit, $redirectUris, $enabled);
        }
        $row = $this->row($provider);
        unset($row['id'], $row['organization_id'], $row['type'], $row['created_by'], $row['created_at']);
        $this->database->update(Schema::PROVIDERS, ['id' => $provider->id], $row);

        return $provider;
    }

    public function delete(string $id): bool
    {
        return $this->database->delete(Schema::PROVIDERS, ['id' => $id]) > 0;
    }

    /**
     * The OIDC client secret in clear; null when none is set.
     */
    public function secret(Provider $provider): ?string
    {
        $stored = $provider->config()[Provider::SECRET] ?? null;
        if (!is_string($stored) || $stored === '') {
            return null;
        }
        $secret = $this->encrypter->decrypt($stored);

        return is_string($secret) ? $secret : null;
    }

    /**
     * @param array<string, mixed> $config
     * @param array<string, string> $attributes
     * @param array{enabled: bool, roles: list<string>} $jit
     * @param list<string> $redirectUris
     */
    private function fill(Provider $provider, string $name, string $issuer, array $config, array $attributes, array $jit, array $redirectUris, bool $enabled, bool $encryptSecret = true): void
    {
        if ($encryptSecret && is_string($config[Provider::SECRET] ?? null) && $config[Provider::SECRET] !== '') {
            $config[Provider::SECRET] = $this->encrypter->encrypt($config[Provider::SECRET]);
        }
        $provider->name = $name;
        $provider->issuer = $issuer;
        $provider->config = json_encode($config, JSON_THROW_ON_ERROR);
        $provider->attributes = json_encode($attributes, JSON_THROW_ON_ERROR);
        $provider->jit = json_encode($jit, JSON_THROW_ON_ERROR);
        $provider->redirectUris = json_encode($redirectUris, JSON_THROW_ON_ERROR);
        $provider->enabled = $enabled;
        $provider->updatedAt = $this->clock->now();
    }

    /**
     * @return array<string, mixed>
     */
    private function row(Provider $provider): array
    {
        return [
            'id' => $provider->id,
            'organization_id' => $provider->organizationId,
            'type' => $provider->type,
            'name' => $provider->name,
            'issuer' => $provider->issuer,
            'config' => $provider->config,
            'attributes' => $provider->attributes,
            'jit' => $provider->jit,
            'redirect_uris' => $provider->redirectUris,
            'enabled' => $provider->enabled,
            'created_by' => $provider->createdBy,
            'created_at' => $provider->createdAt,
            'updated_at' => $provider->updatedAt,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Provider
    {
        $provider = new Provider();
        $provider->id = (string) $row['id'];
        $provider->organizationId = (string) $row['organization_id'];
        $provider->type = (string) $row['type'];
        $provider->name = (string) $row['name'];
        $provider->issuer = (string) $row['issuer'];
        $provider->config = self::json($row['config']);
        $provider->attributes = self::json($row['attributes']);
        $provider->jit = self::json($row['jit']);
        $provider->redirectUris = self::json($row['redirect_uris']);
        $provider->enabled = (bool) $row['enabled'];
        $provider->createdBy = is_string($row['created_by'] ?? null) && $row['created_by'] !== '' ? $row['created_by'] : null;
        $provider->createdAt = self::datetime($row['created_at']);
        $provider->updatedAt = self::datetime($row['updated_at']);

        return $provider;
    }

    private static function json(mixed $value): string
    {
        return is_string($value) ? $value : json_encode($value, JSON_THROW_ON_ERROR);
    }

    private static function datetime(mixed $value): DateTimeImmutable
    {
        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}
