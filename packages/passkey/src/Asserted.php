<?php

declare(strict_types=1);

namespace Polaris\Passkey;

/**
 * What a verified assertion yields: the new counter and the flags the authenticator reported.
 */
final readonly class Asserted
{
    public function __construct(public int $counter, public bool $backedUp, public bool $userVerified)
    {
    }
}
