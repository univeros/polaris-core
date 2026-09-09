<?php

declare(strict_types=1);

namespace Polaris\Contract;

/**
 * A parsed, verified token: its raw string and its claims.
 */
interface TokenInterface
{
    public function getToken(): string;

    /**
     * The claim named `$key`, or null when absent.
     */
    public function getMetadata(?string $key = null): mixed;
}
