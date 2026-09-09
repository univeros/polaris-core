<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\OtpChallenge;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class OtpChallengeSchema
{
    public static function define(): Model
    {
        return Model::table('auth_otp_challenges', OtpChallenge::class, [
            Field::string('id', 36)->primary(),
            Field::string('userId', 36),
            Field::string('factorId', 36)->nullable(),
            Field::string('purpose', 20),
            Field::string('channel', 16),
            Field::string('codeHash', 64)->nullable(),
            Field::string('destination', 320)->nullable(),
            Field::int('attempts')->default(0),
            Field::int('maxAttempts')->default(5),
            Field::datetime('expiresAt'),
            Field::datetime('consumedAt')->nullable(),
            Field::string('ip', 45)->nullable(),
            Field::datetime('createdAt'),
        ])
            ->index(['user_id', 'purpose', 'consumed_at'], 'auth_otp_challenges_user_purpose_index')
            ->index(['expires_at'], 'auth_otp_challenges_expires_index');
    }
}
