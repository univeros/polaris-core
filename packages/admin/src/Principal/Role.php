<?php

declare(strict_types=1);

namespace Polaris\Admin\Principal;

/**
 * The four operator roles, each including the ones below it. Deny by default: an action names the
 * capability it needs and a role either has it or not.
 */
enum Role: string
{
    case Viewer = 'viewer';
    case Support = 'support';
    case Admin = 'admin';
    case Owner = 'owner';

    public function allows(Capability $capability): bool
    {
        return match ($capability) {
            Capability::Read => true,
            Capability::Support => $this !== self::Viewer,
            Capability::Manage, Capability::Impersonate => $this === self::Admin || $this === self::Owner,
            Capability::Own => $this === self::Owner,
        };
    }

    public static function tryFromInput(mixed $value): ?self
    {
        return is_string($value) ? self::tryFrom($value) : null;
    }
}
