<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

/**
 * The `sentinel.*` names of the audit catalog: the engine's decisions and the operators' actions.
 */
final class AuditNames
{
    public const string EVALUATED = 'sentinel.evaluated';
    public const string IP_RULE_CREATED = 'sentinel.ip_rule_created';
    public const string IP_RULE_DELETED = 'sentinel.ip_rule_deleted';
    public const string UNBLOCKED = 'sentinel.unblocked';

    /** @var array<string, string> name => description */
    public const array ALL = [
        self::EVALUATED => 'The sentinel judged an attempt (score, signals, action)',
        self::IP_RULE_CREATED => 'An operator added an IP rule',
        self::IP_RULE_DELETED => 'An operator removed an IP rule',
        self::UNBLOCKED => 'An operator cleared the counters of an email or an address',
    ];
}
