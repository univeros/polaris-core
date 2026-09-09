<?php

declare(strict_types=1);

namespace Polaris\Contract;

interface TokenValidatorInterface
{
    public function validate(string $token): bool;
}
