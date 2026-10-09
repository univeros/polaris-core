<?php

declare(strict_types=1);

namespace Polaris\MultiSession;

use DateTimeImmutable;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\RefreshToken;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Token\ClientContext;
use Polaris\Token\SessionPrincipal;
use Polaris\Token\SessionPrincipalResolverInterface;
use Polaris\Token\TokenService;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

use function array_values;
use function array_filter;
use function bin2hex;
use function explode;
use function hash;
use function is_numeric;
use function random_bytes;
use function usort;

/**
 * The accounts signed in on each device. A device id is minted here and only a known one is accepted
 * back, so nobody can attach a session to a device they did not get the id of; it changes at every
 * sign-in that joins a device, so a planted id is not one either; it is stored as a hash.
 * Switching opens a new session for another account of the device with the authentication facts core
 * keeps on its session row (amr, mfa, auth_time, organization), so the account does not sign in again.
 */
final class Devices
{
    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly UserRepository $users,
        private readonly TokenService $tokens,
        private readonly SessionPrincipalResolverInterface $principals,
        private readonly ClockInterface $clock,
    ) {
    }

    public static function mint(): string
    {
        return bin2hex(random_bytes(32));
    }

    public function known(#[SensitiveParameter] string $deviceId): bool
    {
        return $this->database->count(Schema::DEVICES, ['device_id' => self::hash($deviceId)]) > 0;
    }

    /**
     * Records that the device holds this session of the account; the device id to answer. A session the
     * account did not have on the device before is a sign-in: its method becomes the device's last one,
     * and a device that already had accounts gets a new id, so an id planted in a victim's browser
     * (device fixation) stops naming the device the victim signs into; a refresh or a switch keeps it.
     *
     * @param list<string> $amr
     */
    public function record(#[SensitiveParameter] string $deviceId, string $userId, string $sessionId, array $amr): string
    {
        $now = $this->clock->now();
        $hash = self::hash($deviceId);
        $row = $this->database->findOne(Schema::DEVICES, ['device_id' => $hash, 'user_id' => $userId]);
        if ($row !== null && $row['session_id'] === $sessionId) {
            $this->database->update(Schema::DEVICES, ['id' => $row['id']], ['last_seen' => $now]);

            return $deviceId;
        }
        if ($this->database->count(Schema::DEVICES, ['device_id' => $hash]) > 0) {
            $deviceId = self::mint();
            $this->database->update(Schema::DEVICES, ['device_id' => $hash], ['device_id' => self::hash($deviceId)]);
            $hash = self::hash($deviceId);
        }
        $signIn = ['session_id' => $sessionId, 'last_method' => $amr[0] ?? 'pwd', 'sign_in_id' => Uuid::v7()->toRfc4122(), 'signed_in_at' => $now, 'last_seen' => $now];
        if ($row === null) {
            $this->database->insert(Schema::DEVICES, ['id' => Uuid::v7()->toRfc4122(), 'device_id' => $hash, 'user_id' => $userId, ...$signIn]);
        } else {
            $this->database->update(Schema::DEVICES, ['id' => $row['id']], $signIn);
        }

        return $deviceId;
    }

    /**
     * The method the device last signed in with, for the client to pre-select; null for an unknown device.
     */
    public function lastMethod(#[SensitiveParameter] ?string $deviceId): ?string
    {
        if ($deviceId === null) {
            return null;
        }
        $rows = $this->database->findMany(Schema::DEVICES, ['device_id' => self::hash($deviceId)], ['sign_in_id' => 'desc'], 1);

        return $rows === [] ? null : (string) $rows[0]['last_method'];
    }

    /**
     * The device's live sessions, the most recent sign-in first; the caller's session must be one of them.
     *
     * @return list<array<string, mixed>>
     * @throws MultiSessionException
     */
    public function list(#[SensitiveParameter] ?string $deviceId, string $currentSessionId): array
    {
        $sessions = [];
        foreach ($this->live($deviceId, $currentSessionId) as $row) {
            $user = $this->users->find((string) $row['user_id']);
            if (!$user instanceof User) {
                continue;
            }
            $sessions[] = [
                'session_id' => (string) $row['session_id'],
                'user' => ['id' => $user->id, 'email' => $user->email, 'display_name' => $user->displayName],
                'last_method' => (string) $row['last_method'],
                'signed_in_at' => self::datetime($row['signed_in_at'])->format(DATE_ATOM),
                'last_seen' => self::datetime($row['last_seen'])->format(DATE_ATOM),
                'current' => $row['session_id'] === $currentSessionId,
            ];
        }

        return $sessions;
    }

    /**
     * A fresh session for the account behind another live session of the device, with that session's
     * authentication facts; the old session ends. Core's login envelope.
     *
     * @return array<string, mixed>
     * @throws MultiSessionException
     */
    public function switch(#[SensitiveParameter] ?string $deviceId, string $currentSessionId, string $sessionId, ClientContext $client): array
    {
        $row = $this->liveRow($deviceId, $currentSessionId, $sessionId);
        $session = $this->database->findOne('auth_refresh_tokens', ['family_id' => $sessionId, 'revoked_at' => null]);
        $user = $this->users->find((string) $row['user_id']);
        if ($session === null || !$user instanceof User || $user->status === User::STATUS_DISABLED) {
            throw new MultiSessionException(MultiSessionException::SESSION_NOT_FOUND);
        }
        $organizationId = ($session['organization_id'] ?? null) === null || $session['organization_id'] === '' ? null : (string) $session['organization_id'];
        $amr = array_values(array_filter(explode(',', (string) ($session['amr'] ?? '')), static fn(string $method): bool => $method !== ''));
        $resolved = $this->principals->resolve($user->id, $organizationId);
        $tokens = $this->tokens->issue(new SessionPrincipal(
            $user->id,
            $organizationId,
            $resolved->roles,
            $resolved->scope,
            $user->emailVerifiedAt !== null,
            (bool) ($session['mfa'] ?? false),
            $amr === [] ? ['pwd'] : $amr,
            is_numeric($session['auth_time'] ?? null) ? (int) $session['auth_time'] : null,
        ), $client);
        $this->tokens->revokeFamily($sessionId, RefreshToken::REASON_ROTATED);
        $this->database->update(Schema::DEVICES, ['id' => $row['id']], ['session_id' => $tokens->sessionId, 'last_seen' => $this->clock->now()]);

        return [
            'access_token' => $tokens->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $tokens->accessExpiresIn,
            'refresh_token' => $tokens->refreshToken,
            'user' => ['id' => $user->id, 'email' => $user->email, 'email_verified' => $user->emailVerifiedAt !== null],
        ];
    }

    /**
     * Ends one of the device's sessions (the caller's own included) and forgets it on the device.
     *
     * @throws MultiSessionException
     */
    public function revoke(#[SensitiveParameter] ?string $deviceId, string $currentSessionId, string $sessionId): void
    {
        $row = $this->liveRow($deviceId, $currentSessionId, $sessionId);
        $this->tokens->revokeFamily($sessionId, RefreshToken::REASON_LOGOUT);
        $this->database->delete(Schema::DEVICES, ['id' => $row['id']]);
    }

    /**
     * @return array<string, mixed>
     * @throws MultiSessionException
     */
    private function liveRow(?string $deviceId, string $currentSessionId, string $sessionId): array
    {
        foreach ($this->live($deviceId, $currentSessionId) as $row) {
            if ($row['session_id'] === $sessionId) {
                return $row;
            }
        }

        throw new MultiSessionException(MultiSessionException::SESSION_NOT_FOUND);
    }

    /**
     * The device's rows whose session is live, newest sign-in first; the ended ones are forgotten.
     *
     * @return list<array<string, mixed>>
     * @throws MultiSessionException the caller's session is not on the device
     */
    private function live(?string $deviceId, string $currentSessionId): array
    {
        if ($deviceId === null) {
            throw new MultiSessionException(MultiSessionException::DEVICE_UNKNOWN);
        }
        $now = $this->clock->now();
        $rows = [];
        foreach ($this->database->findMany(Schema::DEVICES, ['device_id' => self::hash($deviceId)]) as $row) {
            if ($this->database->findOne('auth_refresh_tokens', ['family_id' => $row['session_id'], 'revoked_at' => null, 'expires_at' => Condition::gt($now)]) === null) {
                $this->database->delete(Schema::DEVICES, ['id' => $row['id']]);
                continue;
            }
            $rows[] = $row;
        }
        $current = array_filter($rows, static fn(array $row): bool => $row['session_id'] === $currentSessionId);
        if ($current === []) {
            throw new MultiSessionException(MultiSessionException::DEVICE_UNKNOWN);
        }
        usort($rows, static fn(array $a, array $b): int => (string) $b['sign_in_id'] <=> (string) $a['sign_in_id']);

        return $rows;
    }

    private static function hash(string $deviceId): string
    {
        return hash('sha256', $deviceId);
    }

    private static function datetime(mixed $value): DateTimeImmutable
    {
        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}
