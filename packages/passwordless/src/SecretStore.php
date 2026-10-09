<?php

declare(strict_types=1);

namespace Polaris\Passwordless;

use DateInterval;
use DateTimeImmutable;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\Increment;
use Polaris\Passwordless\Model\Secret;
use Polaris\Security\Pepper;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

use function base64_encode;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function random_bytes;
use function random_int;
use function rtrim;
use function str_pad;
use function strtr;

use const JSON_THROW_ON_ERROR;
use const STR_PAD_LEFT;

/**
 * The secrets of the four methods. Only keyed hashes are stored (one pepper context per kind); a code is
 * hashed with its identifier, so it only works for the address it was sent to. A secret is spent by an
 * update that requires it still unused, so two concurrent verifies cannot both succeed. Every guess at a
 * code reserves one of `$maxAttempts` attempts atomically before it is compared, so parallel guesses
 * cannot exceed the budget, and a code sent again while the previous one lives inherits its attempts, so
 * re-sending does not reset the count.
 */
final class SecretStore
{
    private const string IDENTIFIER = 'passwordless:identifier';

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly Pepper $pepper,
        private readonly ClockInterface $clock,
        private readonly int $maxAttempts,
    ) {
    }

    public static function token(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    public static function code(int $length): string
    {
        return str_pad((string) random_int(0, (10 ** $length) - 1), $length, '0', STR_PAD_LEFT);
    }

    /**
     * Stores a token (a magic link, a one-time token), found again by its hash alone.
     *
     * @param array<string, mixed> $data
     */
    public function issueToken(string $kind, string $identifier, ?string $userId, #[SensitiveParameter] string $token, int $ttl, array $data = []): void
    {
        $this->insert($kind, $identifier, $userId, $this->pepper->hash('passwordless:' . $kind, $token), $ttl, $data);
    }

    /**
     * Stores a code for an identifier; the identifier's earlier unused codes of the kind die with it.
     *
     * @param array<string, mixed> $data
     */
    public function issueCode(string $kind, string $identifier, ?string $userId, #[SensitiveParameter] string $code, int $ttl, array $data = []): void
    {
        $unused = ['kind' => $kind, 'identifier_hash' => $this->identifier($identifier), 'used_at' => null];
        $live = $this->database->findMany(Schema::SECRETS, [...$unused, 'expires_at' => Condition::gt($this->clock->now())], ['attempts' => 'desc'], 1);
        $this->database->delete(Schema::SECRETS, $unused);
        $this->insert($kind, $identifier, $userId, $this->codeHash($kind, $identifier, $code), $ttl, $data, (int) ($live[0]['attempts'] ?? 0));
    }

    /**
     * The token's secret, spent; null when it is unknown, used or expired.
     */
    public function spendToken(string $kind, #[SensitiveParameter] string $token): ?Secret
    {
        $row = $this->database->findOne(Schema::SECRETS, ['kind' => $kind, 'secret_hash' => $this->pepper->hash('passwordless:' . $kind, $token), 'used_at' => null]);

        return $row === null ? null : $this->spend(self::hydrate($row));
    }

    /**
     * The code's secret for the identifier, spent; null when there is none, it expired, its attempts are
     * used up, or the code is wrong. Every guess, right or wrong, uses an attempt.
     */
    public function spendCode(string $kind, string $identifier, #[SensitiveParameter] string $code): ?Secret
    {
        $rows = $this->database->findMany(Schema::SECRETS, ['kind' => $kind, 'identifier_hash' => $this->identifier($identifier), 'used_at' => null], ['id' => 'desc'], 1);
        if ($rows === []) {
            return null;
        }
        $secret = self::hydrate($rows[0]);
        $reserved = $this->database->update(Schema::SECRETS, ['id' => $secret->id, 'used_at' => null, 'attempts' => Condition::lt($this->maxAttempts)], ['attempts' => new Increment()]);
        if ($reserved !== 1 || !$this->pepper->matches('passwordless:' . $kind, $identifier . "\0" . $code, $secret->secretHash)) {
            return null;
        }

        return $this->spend($secret);
    }

    private function spend(Secret $secret): ?Secret
    {
        $now = $this->clock->now();
        if ($secret->expiresAt <= $now) {
            return null;
        }
        if ($this->database->update(Schema::SECRETS, ['id' => $secret->id, 'used_at' => null], ['used_at' => $now]) !== 1) {
            return null;
        }
        $secret->usedAt = $now;

        return $secret;
    }

    /**
     * @param array<string, mixed> $data
     */
    private function insert(string $kind, string $identifier, ?string $userId, string $secretHash, int $ttl, array $data, int $attempts = 0): void
    {
        $now = $this->clock->now();
        $this->database->insert(Schema::SECRETS, [
            'id' => Uuid::v7()->toRfc4122(),
            'kind' => $kind,
            'identifier_hash' => $this->identifier($identifier),
            'user_id' => $userId,
            'secret_hash' => $secretHash,
            'attempts' => $attempts,
            'data' => json_encode($data, JSON_THROW_ON_ERROR),
            'expires_at' => $now->add(new DateInterval('PT' . $ttl . 'S')),
            'used_at' => null,
            'created_at' => $now,
        ]);
    }

    private function identifier(string $identifier): string
    {
        return $this->pepper->hash(self::IDENTIFIER, $identifier);
    }

    private function codeHash(string $kind, string $identifier, string $code): string
    {
        return $this->pepper->hash('passwordless:' . $kind, $identifier . "\0" . $code);
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Secret
    {
        $secret = new Secret();
        $secret->id = (string) $row['id'];
        $secret->kind = (string) $row['kind'];
        $secret->identifierHash = (string) $row['identifier_hash'];
        $secret->userId = is_string($row['user_id'] ?? null) && $row['user_id'] !== '' ? $row['user_id'] : null;
        $secret->secretHash = (string) $row['secret_hash'];
        $secret->attempts = (int) ($row['attempts'] ?? 0);
        $data = $row['data'] ?? null;
        $data = is_string($data) ? json_decode($data, true) : $data;
        $secret->data = is_array($data) ? $data : [];
        $secret->expiresAt = self::datetime($row['expires_at']);
        $secret->usedAt = ($row['used_at'] ?? null) === null ? null : self::datetime($row['used_at']);
        $secret->createdAt = self::datetime($row['created_at']);

        return $secret;
    }

    private static function datetime(mixed $value): DateTimeImmutable
    {
        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}
