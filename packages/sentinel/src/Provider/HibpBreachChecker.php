<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

use Override;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use SensitiveParameter;

use function explode;
use function sha1;
use function strtoupper;
use function substr;

/**
 * Have I Been Pwned's range API (k-anonymity: the first five hex characters of the SHA-1 leave, the
 * suffixes come back). A transport failure means "not breached": the signal is advisory.
 */
final class HibpBreachChecker implements BreachChecker
{
    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requests,
        private readonly string $baseUrl = 'https://api.pwnedpasswords.com/range/',
    ) {
    }

    #[Override]
    public function isBreached(#[SensitiveParameter] string $password): bool
    {
        $hash = strtoupper(sha1($password));
        $request = $this->requests->createRequest('GET', $this->baseUrl . substr($hash, 0, 5))->withHeader('Add-Padding', 'true');
        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface) {
            return false;
        }
        if ($response->getStatusCode() !== 200) {
            return false;
        }
        $suffix = substr($hash, 5);
        foreach (explode("\n", (string) $response->getBody()) as $line) {
            [$candidate, $count] = [...explode(':', trim($line), 2), '0'];
            if ($candidate === $suffix && (int) $count > 0) {
                return true;
            }
        }

        return false;
    }
}
