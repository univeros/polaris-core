<?php

declare(strict_types=1);

namespace Polaris\MultiSession;

use RuntimeException;

/**
 * Why a multi-session step was refused: the caller's session is not on a known device
 * (`device_unknown`), or the session asked for is not one of the device's live ones
 * (`session_not_found`, also for a disabled account).
 */
final class MultiSessionException extends RuntimeException
{
    public const string DEVICE_UNKNOWN = 'device_unknown';
    public const string SESSION_NOT_FOUND = 'session_not_found';

    public function __construct(public readonly string $reason)
    {
        parent::__construct($reason === self::DEVICE_UNKNOWN ? 'This session is not signed in on a known device.' : 'No live session of this device has this id.');
    }
}
