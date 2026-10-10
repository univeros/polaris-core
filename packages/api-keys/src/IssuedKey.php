<?php

declare(strict_types=1);

namespace Polaris\ApiKeys;

use Polaris\ApiKeys\Model\ApiKey;
use SensitiveParameter;

/**
 * A freshly created or rotated API key: the record, and the secret shown exactly once.
 */
final readonly class IssuedKey
{
    public function __construct(public ApiKey $key, #[SensitiveParameter] public string $secret)
    {
    }
}
