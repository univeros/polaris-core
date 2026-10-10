<?php

declare(strict_types=1);

namespace Polaris\ApiKeys;

/**
 * The `api_keys.*` names the plugin adds to the audit catalog.
 */
final class AuditNames
{
    public const string CREATED = 'api_keys.created';
    public const string UPDATED = 'api_keys.updated';
    public const string ROTATED = 'api_keys.rotated';
    public const string REVOKED = 'api_keys.revoked';

    public const array ALL = [
        self::CREATED => 'An API key was created (owner, name, permissions, expiry)',
        self::UPDATED => 'An API key was updated (what changed)',
        self::ROTATED => 'An API key was rotated: a new secret, the old one valid for the grace window (new key id)',
        self::REVOKED => 'An API key was revoked',
    ];
}
