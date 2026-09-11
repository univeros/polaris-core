<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use Polaris\Schema\Field;
use Polaris\Schema\Model;
use Polaris\Sentinel\Model\DecisionRecord;
use Polaris\Sentinel\Model\Device;
use Polaris\Sentinel\Model\IpRule;

/**
 * The three tables the plugin owns.
 */
final class Schema
{
    public const string DECISIONS = 'polaris_sentinel_decision';
    public const string IP_RULES = 'polaris_sentinel_ip_rule';
    public const string DEVICES = 'polaris_sentinel_device';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::DECISIONS, DecisionRecord::class, [
                Field::string('id', 36)->primary(),
                Field::string('kind', 32),
                Field::string('email', 320)->nullable(),
                Field::string('ip', 45)->nullable(),
                Field::int('score'),
                Field::string('action', 16),
                Field::bool('enforced'),
                Field::json('signals'),
                Field::json('reasons'),
                Field::datetime('createdAt'),
            ])->index(['created_at'], 'polaris_sentinel_decision_created_index')->index(['email'], 'polaris_sentinel_decision_email_index')->index(['ip'], 'polaris_sentinel_decision_ip_index'),
            Model::table(self::IP_RULES, IpRule::class, [
                Field::string('id', 36)->primary(),
                Field::string('cidr', 64),
                Field::string('action', 16),
                Field::string('note', 255)->nullable(),
                Field::string('createdBy', 64)->nullable(),
                Field::datetime('createdAt'),
            ]),
            Model::table(self::DEVICES, Device::class, [
                Field::string('id', 36)->primary(),
                Field::string('userId', 36),
                Field::string('deviceHash', 64),
                Field::string('ip', 45)->nullable(),
                Field::string('latitude', 32)->nullable(),
                Field::string('longitude', 32)->nullable(),
                Field::datetime('lastSeenAt'),
                Field::datetime('createdAt'),
            ])->unique(['user_id', 'device_hash'], 'polaris_sentinel_device_unique'),
        ];
    }
}
