<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use Polaris\OAuth\Model\Client;
use SensitiveParameter;

/**
 * A freshly registered client: the record, and the secret shown exactly once (null for a public
 * client or one that authenticates with a key).
 */
final readonly class IssuedClient
{
    public function __construct(public Client $client, #[SensitiveParameter] public ?string $secret)
    {
    }
}
