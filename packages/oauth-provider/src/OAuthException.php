<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use RuntimeException;

/**
 * A refused OAuth request: `$error` is the RFC 6749 / 8628 / 9449 / OpenID error code the response
 * carries (`invalid_grant`, `authorization_pending`, ...), also the problem type `oauth/<error>`;
 * `$description` is `error_description`; `$status` the HTTP status.
 */
final class OAuthException extends RuntimeException
{
    public const string INVALID_REQUEST = 'invalid_request';
    public const string INVALID_CLIENT = 'invalid_client';
    public const string INVALID_GRANT = 'invalid_grant';
    public const string UNAUTHORIZED_CLIENT = 'unauthorized_client';
    public const string UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';
    public const string UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type';
    public const string INVALID_SCOPE = 'invalid_scope';
    public const string ACCESS_DENIED = 'access_denied';
    public const string INVALID_TARGET = 'invalid_target';
    public const string INVALID_DPOP_PROOF = 'invalid_dpop_proof';
    public const string INVALID_TOKEN = 'invalid_token';
    public const string INSUFFICIENT_SCOPE = 'insufficient_scope';
    public const string AUTHORIZATION_PENDING = 'authorization_pending';
    public const string SLOW_DOWN = 'slow_down';
    public const string EXPIRED_TOKEN = 'expired_token';
    public const string UNKNOWN_USER_ID = 'unknown_user_id';
    public const string INVALID_CLIENT_METADATA = 'invalid_client_metadata';
    public const string INVALID_REDIRECT_URI = 'invalid_redirect_uri';
    public const string REGISTRATION_DISABLED = 'registration_disabled';
    public const string NOT_FOUND = 'not_found';
    public const string FORBIDDEN = 'forbidden';
    public const string LOGIN_REQUIRED = 'login_required';
    public const string CONSENT_REQUIRED = 'consent_required';

    public function __construct(public readonly string $error, public readonly string $description, public readonly int $status = 400)
    {
        parent::__construct($error . ': ' . $description);
    }
}
