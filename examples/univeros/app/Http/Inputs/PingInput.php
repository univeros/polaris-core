<?php

declare(strict_types=1);

namespace App\Http\Inputs;

/**
 * Input DTO for GET /ping: the endpoint takes no input.
 */
final readonly class PingInput
{
    public function __construct()
    {
    }

    /**
     * @return array<string, list<string>>
     */
    public static function rules(): array
    {
        return [];
    }
}
