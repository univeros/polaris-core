<?php

declare(strict_types=1);

namespace Polaris\Sso\Domain;

use Closure;
use Override;
use Polaris\Sso\Model\Domain;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

use function dns_get_record;
use function hash_equals;
use function in_array;
use function is_string;
use function trim;

use const DNS_TXT;

/**
 * DNS first (`_polaris.<domain>` TXT records through `dns_get_record`, or the resolver given), then the
 * well-known file over the PSR-18 client when one is configured.
 */
final class DnsHttpsDomainVerifier implements DomainVerifier
{
    /** @var Closure(string): list<string> */
    private readonly Closure $txtRecords;

    /**
     * @param (callable(string): list<string>)|null $txtRecords the TXT values of a name; the system resolver by default
     */
    public function __construct(
        private readonly ?ClientInterface $client = null,
        private readonly ?RequestFactoryInterface $requests = null,
        ?callable $txtRecords = null,
    ) {
        $this->txtRecords = $txtRecords === null ? self::systemResolver(...) : Closure::fromCallable($txtRecords);
    }

    #[Override]
    public function verify(string $domain, string $token): ?string
    {
        if (in_array($token, ($this->txtRecords)(Domain::RECORD . '.' . $domain), true)) {
            return 'dns';
        }
        if ($this->client === null || $this->requests === null) {
            return null;
        }
        try {
            $response = $this->client->sendRequest($this->requests->createRequest('GET', 'https://' . $domain . Domain::WELL_KNOWN));
        } catch (ClientExceptionInterface) {
            return null;
        }

        return $response->getStatusCode() === 200 && hash_equals($token, trim((string) $response->getBody())) ? 'https' : null;
    }

    /**
     * @return list<string>
     */
    private static function systemResolver(string $name): array
    {
        $values = [];
        $records = @dns_get_record($name, DNS_TXT);
        foreach ($records === false ? [] : $records as $record) {
            if (is_string($record['txt'] ?? null)) {
                $values[] = trim($record['txt']);
            }
        }

        return $values;
    }
}
