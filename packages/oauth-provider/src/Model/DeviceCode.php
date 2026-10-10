<?php

declare(strict_types=1);

namespace Polaris\OAuth\Model;

use DateTimeImmutable;

/**
 * A device-flow authorization (`polaris_oauth_device_code`): the device code as a keyed hash, the
 * user code the person types, and what the user decided.
 */
final class DeviceCode
{
    public const string STATUS_PENDING = 'pending';
    public const string STATUS_APPROVED = 'approved';
    public const string STATUS_DENIED = 'denied';
    public const string STATUS_USED = 'used';

    public string $id = '';
    public string $deviceCodeHash = '';
    public string $userCode = '';
    public string $clientId = '';
    /** @var list<string> */
    public array $scopes = [];
    public ?string $resource = null;
    public string $status = self::STATUS_PENDING;
    public ?string $userId = null;
    public ?string $organizationId = null;
    public ?int $authTime = null;
    public ?DateTimeImmutable $lastPolledAt = null;
    public DateTimeImmutable $expiresAt;
    public DateTimeImmutable $createdAt;
}
