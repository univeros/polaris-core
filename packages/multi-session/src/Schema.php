<?php

declare(strict_types=1);

namespace Polaris\MultiSession;

use Polaris\MultiSession\Model\DeviceSession;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

/**
 * The table the plugin owns: the accounts signed in on each device, one row per device and account,
 * with the session that is current for it and how the account last signed in.
 */
final class Schema
{
    public const string DEVICES = 'polaris_multi_session_device';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::DEVICES, DeviceSession::class, [
                Field::string('id', 36)->primary(),
                Field::string('deviceId', 64),
                Field::string('userId', 36),
                Field::string('sessionId', 36),
                Field::string('lastMethod', 32),
                Field::string('signInId', 36),
                Field::datetime('signedInAt'),
                Field::datetime('lastSeen'),
            ])->unique(['device_id', 'user_id'], 'polaris_multi_session_device_unique')
                ->index(['session_id'], 'polaris_multi_session_device_session_index'),
        ];
    }
}
