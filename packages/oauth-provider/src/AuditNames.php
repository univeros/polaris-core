<?php

declare(strict_types=1);

namespace Polaris\OAuth;

/**
 * The `oauth.*` names the plugin adds to the audit catalog.
 */
final class AuditNames
{
    public const string CLIENT_CREATED = 'oauth.client_created';
    public const string CLIENT_UPDATED = 'oauth.client_updated';
    public const string CLIENT_DELETED = 'oauth.client_deleted';
    public const string CONSENT_GRANTED = 'oauth.consent_granted';
    public const string CONSENT_DENIED = 'oauth.consent_denied';
    public const string CONSENT_REVOKED = 'oauth.consent_revoked';
    public const string TOKEN_ISSUED = 'oauth.token_issued';
    public const string TOKEN_REFUSED = 'oauth.token_refused';
    public const string TOKEN_REVOKED = 'oauth.token_revoked';
    public const string REFRESH_REUSED = 'oauth.refresh_reused';
    public const string DEVICE_DECIDED = 'oauth.device_decided';
    public const string CIBA_REQUESTED = 'oauth.ciba_requested';
    public const string CIBA_DECIDED = 'oauth.ciba_decided';

    public const array ALL = [
        self::CLIENT_CREATED => 'An OAuth client was registered (client id, name, organization, how)',
        self::CLIENT_UPDATED => 'An OAuth client was changed (what)',
        self::CLIENT_DELETED => 'An OAuth client was deleted',
        self::CONSENT_GRANTED => 'A user granted a client scopes (client id, scopes)',
        self::CONSENT_DENIED => 'A user refused a client (client id)',
        self::CONSENT_REVOKED => 'A user revoked a client\'s consent and its tokens (client id)',
        self::TOKEN_ISSUED => 'Tokens were issued (client id, grant, scopes, DPoP-bound, actor)',
        self::TOKEN_REFUSED => 'A token request was refused (client id, grant, error)',
        self::TOKEN_REVOKED => 'A token was revoked (client id, kind)',
        self::REFRESH_REUSED => 'A rotated refresh token was presented again: its family was revoked (client id)',
        self::DEVICE_DECIDED => 'A user approved or denied a device (client id, decision)',
        self::CIBA_REQUESTED => 'A client asked a user to approve a sign-in (client id, binding message)',
        self::CIBA_DECIDED => 'A user approved or denied a backchannel request (client id, decision)',
    ];
}
