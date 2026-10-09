<?php

declare(strict_types=1);

namespace Polaris\Social;

use DateInterval;
use DateTimeImmutable;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\EncrypterInterface;
use Polaris\Exception\DecryptException;
use Polaris\Social\Model\Account;
use Polaris\Social\Provider\Profile;
use Polaris\Social\Provider\Tokens;
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
 * The linked provider accounts: by provider and subject (what a sign-in names), by user; the tokens
 * encrypted at rest with core's encrypter.
 */
final class Accounts
{
    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly EncrypterInterface $encrypter,
        private readonly ClockInterface $clock,
    ) {
    }

    public function find(string $provider, string $subject): ?Account
    {
        $row = $this->database->findOne(Schema::ACCOUNTS, ['provider' => $provider, 'provider_account_id' => $subject]);

        return $row === null ? null : $this->hydrate($row);
    }

    public function forUserAndProvider(string $userId, string $provider): ?Account
    {
        $row = $this->database->findOne(Schema::ACCOUNTS, ['user_id' => $userId, 'provider' => $provider]);

        return $row === null ? null : $this->hydrate($row);
    }

    /**
     * @return list<Account>
     */
    public function forUser(string $userId): array
    {
        $accounts = [];
        foreach ($this->database->findMany(Schema::ACCOUNTS, ['user_id' => $userId], ['id' => 'asc']) as $row) {
            $accounts[] = $this->hydrate($row);
        }

        return $accounts;
    }

    public function link(string $userId, string $provider, Profile $profile, Tokens $tokens): Account
    {
        $now = $this->clock->now();
        $account = new Account();
        $account->id = Uuid::v7()->toRfc4122();
        $account->userId = $userId;
        $account->provider = $provider;
        $account->providerAccountId = $profile->subject;
        $account->createdAt = $now;
        $this->apply($account, $profile, $tokens, $now);
        $this->database->insert(Schema::ACCOUNTS, [
            'id' => $account->id,
            'user_id' => $userId,
            'provider' => $provider,
            'provider_account_id' => $profile->subject,
            ...$this->columns($account),
            'created_at' => $now,
        ]);

        return $account;
    }

    /**
     * A sign-in refreshes what the provider reported and the tokens.
     */
    public function update(Account $account, Profile $profile, Tokens $tokens): void
    {
        $this->apply($account, $profile, $tokens, $this->clock->now());
        $this->database->update(Schema::ACCOUNTS, ['id' => $account->id], $this->columns($account));
    }

    public function storeTokens(Account $account, Tokens $tokens): void
    {
        $now = $this->clock->now();
        $account->accessTokenEnc = $this->encrypter->encrypt($tokens->accessToken);
        if ($tokens->refreshToken !== null) {
            $account->refreshTokenEnc = $this->encrypter->encrypt($tokens->refreshToken);
        }
        $account->expiresAt = $tokens->expiresIn === null ? null : $now->add(new DateInterval('PT' . $tokens->expiresIn . 'S'));
        $account->updatedAt = $now;
        $this->database->update(Schema::ACCOUNTS, ['id' => $account->id], $this->columns($account));
    }

    public function unlink(Account $account): void
    {
        $this->database->delete(Schema::ACCOUNTS, ['id' => $account->id]);
    }

    public function unlinkAll(string $userId, ?string $except = null): void
    {
        foreach ($this->forUser($userId) as $account) {
            if ($account->id !== $except) {
                $this->database->delete(Schema::ACCOUNTS, ['id' => $account->id]);
            }
        }
    }

    public function accessToken(Account $account): ?string
    {
        return $this->decrypt($account->accessTokenEnc);
    }

    public function refreshToken(Account $account): ?string
    {
        return $this->decrypt($account->refreshTokenEnc);
    }

    private function decrypt(?string $encrypted): ?string
    {
        if ($encrypted === null || $encrypted === '') {
            return null;
        }
        try {
            return (string) $this->encrypter->decrypt($encrypted);
        } catch (DecryptException) {
            return null;
        }
    }

    private function apply(Account $account, Profile $profile, Tokens $tokens, DateTimeImmutable $now): void
    {
        $account->email = $profile->email;
        $account->emailVerified = $profile->emailVerified;
        $account->scopes = $tokens->scopes;
        $account->profile = $profile->toArray();
        // A sign-in without tokens (One Tap: an id_token only) keeps the tokens a callback stored.
        if ($tokens->accessToken !== '') {
            $account->accessTokenEnc = $this->encrypter->encrypt($tokens->accessToken);
            $account->expiresAt = $tokens->expiresIn === null ? null : $now->add(new DateInterval('PT' . $tokens->expiresIn . 'S'));
        }
        if ($tokens->refreshToken !== null) {
            $account->refreshTokenEnc = $this->encrypter->encrypt($tokens->refreshToken);
        }
        $account->updatedAt = $now;
    }

    /**
     * @return array<string, mixed>
     */
    private function columns(Account $account): array
    {
        return [
            'email' => $account->email,
            'email_verified' => $account->emailVerified,
            'scopes' => json_encode($account->scopes, JSON_THROW_ON_ERROR),
            'profile' => json_encode($account->profile, JSON_THROW_ON_ERROR),
            'access_token_enc' => $account->accessTokenEnc,
            'refresh_token_enc' => $account->refreshTokenEnc,
            'expires_at' => $account->expiresAt,
            'updated_at' => $account->updatedAt,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private function hydrate(array $row): Account
    {
        $account = new Account();
        $account->id = (string) $row['id'];
        $account->userId = (string) $row['user_id'];
        $account->provider = (string) $row['provider'];
        $account->providerAccountId = (string) $row['provider_account_id'];
        $account->email = is_string($row['email'] ?? null) && $row['email'] !== '' ? $row['email'] : null;
        $account->emailVerified = (bool) ($row['email_verified'] ?? false);
        $scopes = is_string($row['scopes'] ?? null) ? json_decode($row['scopes'], true) : ($row['scopes'] ?? []);
        $account->scopes = is_array($scopes) ? array_values(array_filter($scopes, 'is_string')) : [];
        $profile = is_string($row['profile'] ?? null) ? json_decode($row['profile'], true) : ($row['profile'] ?? []);
        $account->profile = is_array($profile) ? $profile : [];
        $account->accessTokenEnc = is_string($row['access_token_enc'] ?? null) ? $row['access_token_enc'] : null;
        $account->refreshTokenEnc = is_string($row['refresh_token_enc'] ?? null) ? $row['refresh_token_enc'] : null;
        $account->expiresAt = ($row['expires_at'] ?? null) === null ? null : self::datetime($row['expires_at']);
        $account->createdAt = self::datetime($row['created_at']);
        $account->updatedAt = self::datetime($row['updated_at']);

        return $account;
    }

    private static function datetime(mixed $value): DateTimeImmutable
    {
        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}
