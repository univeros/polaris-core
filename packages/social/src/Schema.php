<?php

declare(strict_types=1);

namespace Polaris\Social;

use Polaris\Schema\Field;
use Polaris\Schema\Model;
use Polaris\Social\Model\Account;

/**
 * The table the plugin owns: a user's linked provider accounts with their tokens (encrypted). The OAuth
 * state lives in the cache, as sso's does.
 */
final class Schema
{
    public const string ACCOUNTS = 'polaris_social_account';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::ACCOUNTS, Account::class, [
                Field::string('id', 36)->primary(),
                Field::string('userId', 36),
                Field::string('provider', 40),
                Field::string('providerAccountId', 255),
                Field::string('email', 320)->nullable(),
                Field::bool('emailVerified')->default(false),
                Field::json('scopes'),
                Field::json('profile'),
                Field::text('accessTokenEnc')->nullable(),
                Field::text('refreshTokenEnc')->nullable(),
                Field::datetime('expiresAt')->nullable(),
                Field::datetime('createdAt'),
                Field::datetime('updatedAt'),
            ])->unique(['provider', 'provider_account_id'], 'polaris_social_account_unique')
                ->unique(['user_id', 'provider'], 'polaris_social_account_user_provider_unique'),
        ];
    }
}
