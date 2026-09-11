<?php

declare(strict_types=1);

namespace Polaris\Sso\Domain;

/**
 * Proves an organization controls a domain: a DNS TXT record `_polaris.<domain>` or the file
 * `https://<domain>/.well-known/polaris-sso.txt` carrying the domain's token.
 */
interface DomainVerifier
{
    /**
     * @return string|null how it was proven (`dns`, `https`), null when it was not
     */
    public function verify(string $domain, string $token): ?string;
}
