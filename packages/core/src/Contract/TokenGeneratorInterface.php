<?php

declare(strict_types=1);

namespace Polaris\Contract;

interface TokenGeneratorInterface
{
    /**
     * @param array<string, mixed> $claims
     */
    public function generate(array $claims = []): string;
}
