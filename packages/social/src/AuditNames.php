<?php

declare(strict_types=1);

namespace Polaris\Social;

/**
 * The `social.*` names the plugin adds to the audit catalog.
 */
final class AuditNames
{
    public const string SIGNED_IN = 'social.signed_in';
    public const string SIGNED_UP = 'social.signed_up';
    public const string LINKED = 'social.linked';
    public const string UNLINKED = 'social.unlinked';
    public const string TOKEN_REFRESHED = 'social.token_refreshed';
    public const string REJECTED = 'social.rejected';

    public const array ALL = [
        self::SIGNED_IN => 'A user signed in through a provider (provider, account id, linked just now)',
        self::SIGNED_UP => 'A provider sign-in created the user (provider, account id)',
        self::LINKED => 'A provider account was linked to the user (provider, account id)',
        self::UNLINKED => 'A provider account was unlinked from the user (provider, account id)',
        self::TOKEN_REFRESHED => 'A provider token was refreshed for the user (provider)',
        self::REJECTED => 'A provider sign-in was refused (provider, reason)',
    ];
}
