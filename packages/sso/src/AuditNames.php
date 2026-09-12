<?php

declare(strict_types=1);

namespace Polaris\Sso;

/**
 * The `sso.*` names of the audit catalog.
 */
final class AuditNames
{
    public const string PROVIDER_CREATED = 'sso.provider_created';
    public const string PROVIDER_UPDATED = 'sso.provider_updated';
    public const string PROVIDER_DELETED = 'sso.provider_deleted';
    public const string DOMAIN_ADDED = 'sso.domain_added';
    public const string DOMAIN_VERIFIED = 'sso.domain_verified';
    public const string DOMAIN_DELETED = 'sso.domain_deleted';
    public const string SIGNED_IN = 'sso.signed_in';
    public const string ASSERTION_REJECTED = 'sso.assertion_rejected';
    public const string SLO_COMPLETED = 'sso.slo_completed';

    /** @var array<string, string> name => description */
    public const array ALL = [
        self::PROVIDER_CREATED => 'An SSO provider was added to an organization',
        self::PROVIDER_UPDATED => 'An SSO provider was changed',
        self::PROVIDER_DELETED => 'An SSO provider was removed',
        self::DOMAIN_ADDED => 'A domain was added to an organization for SSO routing',
        self::DOMAIN_VERIFIED => 'A domain was verified',
        self::DOMAIN_DELETED => 'A domain was removed',
        self::SIGNED_IN => 'A user signed in through an SSO provider',
        self::ASSERTION_REJECTED => 'An SSO assertion or token was rejected (reason)',
        self::SLO_COMPLETED => 'A single logout completed',
    ];
}
