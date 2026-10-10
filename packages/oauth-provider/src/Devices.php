<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use DateTimeImmutable;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\OAuth\Model\Client;
use Polaris\OAuth\Model\DeviceCode;
use Polaris\Security\Pepper;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

use function array_filter;
use function array_values;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function preg_replace;
use function random_bytes;
use function random_int;
use function sprintf;
use function strlen;
use function strtoupper;
use function substr;

use const JSON_THROW_ON_ERROR;

/**
 * The device authorization grant (RFC 8628): a device gets a device code (kept as a keyed hash) and
 * a short user code; the user types the user code on the host's page and decides from their own
 * session; the device polls the token endpoint at the interval, and is slowed down when it does not.
 */
final class Devices
{
    private const string PEPPER_CONTEXT = 'oauth_device';
    private const string USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';
    private const int USER_CODE_LENGTH = 8;

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly Pepper $pepper,
        private readonly Settings $settings,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @param list<string> $scopes
     * @return array<string, mixed> the RFC 8628 §3.2 response
     * @throws OAuthException `unauthorized_client`, `invalid_request`
     */
    public function start(Client $client, array $scopes, ?string $resource): array
    {
        if ($this->settings->deviceUrl === null) {
            throw new OAuthException(OAuthException::UNAUTHORIZED_CLIENT, 'The device flow is not enabled on this server.');
        }
        if (!$client->allowsGrant(Clients::GRANT_DEVICE)) {
            throw new OAuthException(OAuthException::UNAUTHORIZED_CLIENT, 'The client may not use the device grant.');
        }
        $now = $this->clock->now();
        $deviceCode = Jwt::base64UrlEncode(random_bytes(32));
        $userCode = self::userCode();
        $this->database->insert(Schema::DEVICE_CODES, [
            'id' => Uuid::v7()->toRfc4122(),
            'device_code_hash' => $this->pepper->hash(self::PEPPER_CONTEXT, $deviceCode),
            'user_code' => $userCode,
            'client_id' => $client->clientId,
            'scopes' => json_encode($scopes, JSON_THROW_ON_ERROR),
            'resource' => $resource,
            'status' => DeviceCode::STATUS_PENDING,
            'user_id' => null,
            'organization_id' => null,
            'auth_time' => null,
            'last_polled_at' => null,
            'expires_at' => $now->modify(sprintf('+%d seconds', $this->settings->deviceCodeTtl)),
            'created_at' => $now,
        ]);
        $display = substr($userCode, 0, 4) . '-' . substr($userCode, 4);

        return [
            'device_code' => $deviceCode,
            'user_code' => $display,
            'verification_uri' => $this->settings->deviceUrl,
            'verification_uri_complete' => $this->settings->deviceUrl . '?user_code=' . $display,
            'expires_in' => $this->settings->deviceCodeTtl,
            'interval' => $this->settings->pollInterval,
        ];
    }

    /**
     * The pending authorization a user code names (what the page shows before the decision).
     *
     * @throws OAuthException `invalid_grant`
     */
    public function byUserCode(string $userCode): DeviceCode
    {
        $normalized = strtoupper((string) preg_replace('/[^A-Za-z]/', '', $userCode));
        $row = strlen($normalized) === self::USER_CODE_LENGTH ? $this->database->findOne(Schema::DEVICE_CODES, ['user_code' => $normalized]) : null;
        $device = $row === null ? null : self::hydrate($row);
        if ($device === null || $device->status !== DeviceCode::STATUS_PENDING || $device->expiresAt <= $this->clock->now()) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The code is unknown, used or expired.', 404);
        }

        return $device;
    }

    public function decide(DeviceCode $device, bool $approve, string $userId, ?string $organizationId, ?int $authTime): void
    {
        $status = $approve ? DeviceCode::STATUS_APPROVED : DeviceCode::STATUS_DENIED;
        if ($this->database->update(Schema::DEVICE_CODES, ['id' => $device->id, 'status' => DeviceCode::STATUS_PENDING], ['status' => $status, 'user_id' => $userId, 'organization_id' => $organizationId, 'auth_time' => $authTime]) !== 1) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The code was already decided.', 409);
        }
        $device->status = $status;
        $device->userId = $userId;
        $device->organizationId = $organizationId;
        $device->authTime = $authTime;
    }

    /**
     * The device's poll at the token endpoint: the approved authorization, spent; or why not yet.
     *
     * @throws OAuthException `authorization_pending`, `slow_down`, `access_denied`, `expired_token`, `invalid_grant`
     */
    public function poll(#[SensitiveParameter] string $deviceCode, Client $client): DeviceCode
    {
        $row = $this->database->findOne(Schema::DEVICE_CODES, ['device_code_hash' => $this->pepper->hash(self::PEPPER_CONTEXT, $deviceCode)]);
        $device = $row === null ? null : self::hydrate($row);
        if ($device === null || $device->clientId !== $client->clientId) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The device code is unknown.');
        }
        $now = $this->clock->now();
        if ($device->expiresAt <= $now) {
            throw new OAuthException(OAuthException::EXPIRED_TOKEN, 'The device code expired; start again.');
        }
        $tooSoon = $device->lastPolledAt !== null && $now->getTimestamp() - $device->lastPolledAt->getTimestamp() < $this->settings->pollInterval;
        $this->database->update(Schema::DEVICE_CODES, ['id' => $device->id], ['last_polled_at' => $now]);
        if ($tooSoon) {
            throw new OAuthException(OAuthException::SLOW_DOWN, sprintf('Poll every %d seconds.', $this->settings->pollInterval));
        }
        return match ($device->status) {
            DeviceCode::STATUS_PENDING => throw new OAuthException(OAuthException::AUTHORIZATION_PENDING, 'The user has not decided yet.'),
            DeviceCode::STATUS_DENIED => throw new OAuthException(OAuthException::ACCESS_DENIED, 'The user refused.'),
            DeviceCode::STATUS_APPROVED => $this->spend($device),
            default => throw new OAuthException(OAuthException::INVALID_GRANT, 'The device code was already used.'),
        };
    }

    public function prune(): int
    {
        return $this->database->delete(Schema::DEVICE_CODES, ['expires_at' => Condition::lt($this->clock->now())]);
    }

    private function spend(DeviceCode $device): DeviceCode
    {
        if ($this->database->update(Schema::DEVICE_CODES, ['id' => $device->id, 'status' => DeviceCode::STATUS_APPROVED], ['status' => DeviceCode::STATUS_USED]) !== 1) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The device code was already used.');
        }
        $device->status = DeviceCode::STATUS_USED;

        return $device;
    }

    private static function userCode(): string
    {
        $code = '';
        $max = strlen(self::USER_CODE_ALPHABET) - 1;
        for ($i = 0; $i < self::USER_CODE_LENGTH; ++$i) {
            $code .= self::USER_CODE_ALPHABET[random_int(0, $max)];
        }

        return $code;
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): DeviceCode
    {
        $device = new DeviceCode();
        $device->id = (string) $row['id'];
        $device->deviceCodeHash = (string) $row['device_code_hash'];
        $device->userCode = (string) $row['user_code'];
        $device->clientId = (string) $row['client_id'];
        $scopes = is_string($row['scopes'] ?? null) ? json_decode($row['scopes'], true) : $row['scopes'];
        $device->scopes = is_array($scopes) ? array_values(array_filter($scopes, is_string(...))) : [];
        $device->resource = is_string($row['resource'] ?? null) && $row['resource'] !== '' ? $row['resource'] : null;
        $device->status = (string) $row['status'];
        $device->userId = is_string($row['user_id'] ?? null) && $row['user_id'] !== '' ? $row['user_id'] : null;
        $device->organizationId = is_string($row['organization_id'] ?? null) && $row['organization_id'] !== '' ? $row['organization_id'] : null;
        $device->authTime = ($row['auth_time'] ?? null) === null ? null : (int) $row['auth_time'];
        $device->lastPolledAt = self::datetime($row['last_polled_at'] ?? null);
        $device->expiresAt = self::datetime($row['expires_at']) ?? new DateTimeImmutable();
        $device->createdAt = self::datetime($row['created_at']) ?? new DateTimeImmutable();

        return $device;
    }

    private static function datetime(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || $value === '') {
            return null;
        }

        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}
