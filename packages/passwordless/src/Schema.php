<?php

declare(strict_types=1);

namespace Polaris\Passwordless;

use Polaris\Passwordless\Model\Phone;
use Polaris\Passwordless\Model\Secret;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

/**
 * The two tables the plugin owns: the secrets of the four methods (hashed, single use) and the verified
 * phones (one per user, each number once).
 */
final class Schema
{
    public const string SECRETS = 'polaris_passwordless_secret';
    public const string PHONES = 'polaris_passwordless_phone';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::SECRETS, Secret::class, [
                Field::string('id', 36)->primary(),
                Field::string('kind', 32),
                Field::string('identifierHash', 128),
                Field::string('userId', 36)->nullable(),
                Field::string('secretHash', 128),
                Field::int('attempts')->default(0),
                Field::json('data'),
                Field::datetime('expiresAt'),
                Field::datetime('usedAt')->nullable(),
                Field::datetime('createdAt'),
            ])->index(['kind', 'identifier_hash'], 'polaris_passwordless_secret_identifier_index')
                ->index(['secret_hash'], 'polaris_passwordless_secret_hash_index'),
            Model::table(self::PHONES, Phone::class, [
                Field::string('userId', 36)->primary(),
                Field::string('e164', 16),
                Field::datetime('verifiedAt'),
                Field::datetime('createdAt'),
            ])->unique(['e164'], 'polaris_passwordless_phone_unique'),
        ];
    }
}
