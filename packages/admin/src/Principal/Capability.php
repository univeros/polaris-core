<?php

declare(strict_types=1);

namespace Polaris\Admin\Principal;

/**
 * What an admin route needs (the matrix in the README): read; support actions (revoke sessions,
 * resend verification); manage (ban, set password, MFA reset, create and delete users and
 * organizations, roles); impersonate; own (grants, API keys, drains, and what other packages hang
 * under /admin).
 */
enum Capability: string
{
    case Read = 'read';
    case Support = 'support';
    case Manage = 'manage';
    case Impersonate = 'impersonate';
    case Own = 'own';
}
