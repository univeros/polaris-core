<?php

declare(strict_types=1);

namespace Polaris\Contract;

use Polaris\Exception\DecryptException;

/**
 * Authenticated encryption of secrets at rest (TOTP seeds).
 */
interface EncrypterInterface
{
    public function encrypt(mixed $value): string;

    /**
     * @throws DecryptException when the payload is malformed, tampered with, or encrypted under another key
     */
    public function decrypt(string $payload): mixed;
}
