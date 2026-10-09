<?php

declare(strict_types=1);

namespace Polaris\MultiSession\Model;

use DateTimeImmutable;

/**
 * One account signed in on one device (`polaris_multi_session_device`): the session that is current for
 * it, the method it last signed in with, when it signed in and when the device last used it.
 */
final class DeviceSession
{
    public string $id = '';
    public string $deviceId = '';
    public string $userId = '';
    public string $sessionId = '';
    public string $lastMethod = '';
    /** A UUID v7 minted at each sign-in: orders sign-ins within the same second. */
    public string $signInId = '';
    public DateTimeImmutable $signedInAt;
    public DateTimeImmutable $lastSeen;
}
