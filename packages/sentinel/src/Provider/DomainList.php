<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

/**
 * The domains of disposable mailboxes.
 */
interface DomainList
{
    public function contains(string $domain): bool;
}
