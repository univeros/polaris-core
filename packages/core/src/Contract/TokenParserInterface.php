<?php

declare(strict_types=1);

namespace Polaris\Contract;

use Polaris\Exception\InvalidTokenException;

interface TokenParserInterface
{
    /**
     * @throws InvalidTokenException when the token cannot be parsed or fails verification
     */
    public function parse(string $token): TokenInterface;
}
