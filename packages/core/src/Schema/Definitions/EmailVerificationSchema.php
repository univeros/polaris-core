<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\EmailVerification;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class EmailVerificationSchema
{
    public static function define(): Model
    {
        return Model::table('auth_email_verifications', EmailVerification::class, [
            Field::string('id', 36)->primary(),
            Field::string('userId', 36),
            Field::string('email', 320),
            Field::string('tokenHash', 64),
            Field::datetime('expiresAt'),
            Field::datetime('consumedAt')->nullable(),
            Field::string('ip', 45)->nullable(),
            Field::datetime('createdAt'),
        ])
            ->unique(['token_hash'], 'auth_email_verifications_token_hash_unique')
            ->index(['user_id'], 'auth_email_verifications_user_index')
            ->index(['expires_at'], 'auth_email_verifications_expires_index');
    }
}
