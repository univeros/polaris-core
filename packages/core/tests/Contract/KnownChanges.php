<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Contract;

/**
 * The recorded 1.0 responses the extraction deliberately changed. Every entry is documented in
 * `docs/extraction/behaviour-changes.md`; the replay compares against the new response instead.
 */
final class KnownChanges
{
    /**
     * @return array<string, array<int, array{status: int, headers: array<string, list<string>>, body: mixed}>> test => step index (1-based) => expected normalised response
     */
    public static function all(): array
    {
        return [
            'Univeros\\Polaris\\Tests\\Functional\\MfaLoginGateEndpointsTest::testTheTicketPrincipalCannotBeSpoofedViaTheBody' => [
                7 => [
                    'status' => 422,
                    'headers' => ['content-type' => ['application/json'], 'x-ratelimit-limit' => ['10']],
                    'body' => ['error' => 'invalid_code', 'message' => 'The verification code is invalid.'],
                ],
            ],
        ];
    }
}
