<?php

declare(strict_types=1);

namespace Polaris\Model;

use DateTimeImmutable;

/**
 * A pending invitation for someone to join an organization (table `auth_invitations`).
 *
 * The invitee is identified by {@see $email} and may not yet be a registered user. The emailed
 * invite token is never stored — only its keyed HMAC-SHA256 in {@see $tokenHash} ({@see $tokenHash}
 * is unique), mirroring how email-verification / password-reset tokens are handled. {@see $roleIds}
 * holds a JSON-encoded array of role ids to grant when the invitation is accepted; it is encoded and
 * decoded by the invitation service, keeping this entity a thin row mirror. An invitation is single
 * use: {@see $acceptedAt} is set on acceptance, and it is only valid until {@see $expiresAt}.
 *
 * See `docs/auth/data-model.md` and `docs/auth/rbac.md`.
 */
class Invitation
{
    public string $id = '';
    public string $organizationId = '';

    /** Invitee address; may not yet belong to a registered user. */
    public string $email = '';

    /** JSON-encoded array of role ids to grant on acceptance; encoded/decoded by the service. */
    public string $roleIds = '[]';

    /** Keyed HMAC-SHA256 (hex) of the emailed invite token; never the token itself. */
    public string $tokenHash = '';
    public string $invitedBy = '';
    public DateTimeImmutable $expiresAt;
    public ?DateTimeImmutable $acceptedAt = null;
    public DateTimeImmutable $createdAt;
}
