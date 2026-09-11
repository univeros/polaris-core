<?php

declare(strict_types=1);

namespace Polaris\Admin;

use Polaris\Admin\Model\AdminKey;

/**
 * A freshly created API key: the record, and the plaintext shown exactly once.
 */
final readonly class IssuedKey
{
    public function __construct(public AdminKey $key, #[\SensitiveParameter] public string $plaintext)
    {
    }
}
