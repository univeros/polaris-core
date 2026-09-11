<?php

declare(strict_types=1);

namespace Polaris\Admin;

use DateTimeImmutable;
use Polaris\Admin\Model\AdminKey;
use Polaris\Admin\Principal\IpAllowlist;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Role;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Repository\GenericRepository;
use Polaris\Repository\IdentityMap;
use Polaris\Schema\Schema as Registry;
use Polaris\Security\Pepper;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

use function base64_encode;
use function json_encode;
use function random_bytes;
use function rtrim;
use function str_starts_with;
use function strtr;

use const JSON_THROW_ON_ERROR;

/**
 * The API keys (`polaris_admin_key`): `pak_<256 random bits>`, stored as a keyed hash, shown once at
 * creation, checked for expiry and IP allowlist at each use.
 */
final class Keys
{
    public const string PREFIX = 'pak_';
    private const string PEPPER_CONTEXT = 'admin_key';
    private const int SECRET_BYTES = 32;

    /** @var GenericRepository<AdminKey> */
    private readonly GenericRepository $keys;

    public function __construct(
        private readonly DatabaseAdapter $database,
        IdentityMap $identities,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly Pepper $pepper,
        private readonly ClockInterface $clock,
    ) {
        $this->keys = new GenericRepository($database, Registry::for(AdminKey::class), $identities);
    }

    /**
     * @param list<string> $ipAllowlist addresses or CIDR blocks; empty means anywhere
     */
    public function create(string $name, Role $role, string $scope = Principal::SCOPE_INSTANCE, array $ipAllowlist = [], ?DateTimeImmutable $expiresAt = null, ?string $createdBy = null): IssuedKey
    {
        $plaintext = self::PREFIX . rtrim(strtr(base64_encode(random_bytes(self::SECRET_BYTES)), '+/', '-_'), '=');
        $key = new AdminKey();
        $key->id = Uuid::v7()->toRfc4122();
        $key->name = $name;
        $key->keyHash = $this->pepper->hash(self::PEPPER_CONTEXT, $plaintext);
        $key->role = $role->value;
        $key->scope = $scope;
        $key->ipAllowlist = json_encode($ipAllowlist, JSON_THROW_ON_ERROR);
        $key->expiresAt = $expiresAt;
        $key->createdBy = $createdBy;
        $key->createdAt = $this->clock->now();
        $this->unitOfWork->persist($key);
        $this->unitOfWork->flush();

        return new IssuedKey($key, $plaintext);
    }

    /**
     * The key behind a presented secret, when it exists, has not expired and allows the caller's
     * address; its `last_used_at` is stamped.
     */
    public function authenticate(#[SensitiveParameter] string $plaintext, ?string $ip): ?AdminKey
    {
        if (!str_starts_with($plaintext, self::PREFIX)) {
            return null;
        }
        $key = $this->keys->findOneBy(['keyHash' => $this->pepper->hash(self::PEPPER_CONTEXT, $plaintext)]);
        $now = $this->clock->now();
        if ($key === null || ($key->expiresAt !== null && $key->expiresAt <= $now) || !IpAllowlist::allows($key->allowlist(), $ip)) {
            return null;
        }
        $key->lastUsedAt = $now;
        $this->database->update(Schema::KEYS, ['id' => $key->id], ['last_used_at' => $now]);

        return $key;
    }

    public function find(string $id): ?AdminKey
    {
        return $this->keys->find($id);
    }

    /**
     * @return list<AdminKey>
     */
    public function all(): array
    {
        return [...$this->keys->findAll()];
    }

    public function delete(string $id): bool
    {
        $key = $this->keys->find($id);
        if ($key === null) {
            return false;
        }
        $this->unitOfWork->remove($key);
        $this->unitOfWork->flush();

        return true;
    }
}
