<?php

declare(strict_types=1);

namespace Polaris\OAuth;

/**
 * An authorization code presented a second time (RFC 9700 §4.5): the token endpoint revokes the
 * family the first redemption issued, whose id is the code's.
 */
final class CodeReused extends \RuntimeException
{
    public function __construct(public readonly string $codeId)
    {
        parent::__construct('The authorization code was already used.');
    }
}
