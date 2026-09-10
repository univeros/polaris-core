<?php

declare(strict_types=1);

namespace App\Health;

use Altair\Http\Contracts\PayloadInterface;
use App\Http\Inputs\PingInput;

/**
 * The skeleton's proof-of-life domain, kept so the application's own endpoints run beside Polaris.
 */
final class Ping
{
    public function __invoke(PingInput $input, PayloadInterface $payload): PayloadInterface
    {
        return $payload
            ->withStatus(200)
            ->withOutput(['message' => 'ok', 'timestamp' => gmdate('c')]);
    }
}
