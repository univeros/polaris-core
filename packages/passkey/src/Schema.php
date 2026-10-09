<?php

declare(strict_types=1);

namespace Polaris\Passkey;

use Polaris\Passkey\Model\Passkey;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

/**
 * The table the plugin owns: a user's passkeys, each a WebAuthn credential (its id, COSE public key and
 * signature counter) that may also back a core MFA factor (`factor_id`).
 */
final class Schema
{
    public const string PASSKEYS = 'polaris_passkey';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::PASSKEYS, Passkey::class, [
                Field::string('id', 36)->primary(),
                Field::string('userId', 36),
                Field::string('credentialId', 1024),
                Field::text('publicKey'),
                Field::int('counter')->default(0),
                Field::string('aaguid', 36),
                Field::json('transports'),
                Field::bool('backupEligible')->default(false),
                Field::bool('backedUp')->default(false),
                Field::string('name', 80),
                Field::string('factorId', 36)->nullable(),
                Field::datetime('lastUsedAt')->nullable(),
                Field::datetime('createdAt'),
            ])->unique(['credential_id'], 'polaris_passkey_credential_unique')
                ->index(['user_id'], 'polaris_passkey_user_index')
                ->index(['factor_id'], 'polaris_passkey_factor_index'),
        ];
    }
}
