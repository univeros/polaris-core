<?php

declare(strict_types=1);

namespace Polaris\Admin\Principal;

/**
 * What a bearer resolved to: a principal, nothing, or an impersonation token (never a principal).
 */
final readonly class Resolution
{
    public function __construct(public ?Principal $principal = null, public bool $impersonated = false)
    {
    }
}
