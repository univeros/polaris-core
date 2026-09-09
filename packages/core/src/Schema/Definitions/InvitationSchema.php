<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\Invitation;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class InvitationSchema
{
    public static function define(): Model
    {
        return Model::table('auth_invitations', Invitation::class, [
            Field::string('id', 36)->primary(),
            Field::string('organizationId', 36),
            Field::string('email', 320),
            Field::json('roleIds'),
            Field::string('tokenHash', 64),
            Field::string('invitedBy', 36),
            Field::datetime('expiresAt'),
            Field::datetime('acceptedAt')->nullable(),
            Field::datetime('createdAt'),
        ])
            ->unique(['token_hash'], 'auth_invitations_token_hash_unique')
            ->index(['organization_id'], 'auth_invitations_org_index')
            ->index(['email'], 'auth_invitations_email_index');
    }
}
