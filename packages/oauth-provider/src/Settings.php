<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use LogicException;

use function in_array;
use function preg_match;
use function rtrim;

/**
 * The plugin's configuration: where the host's consent and device pages are, the lifetimes, which
 * optional parts are on (dynamic registration, client ID metadata documents, DPoP), the extra scopes a
 * host defines beyond the permission catalog, and the clients trusted to skip consent.
 */
final readonly class Settings
{
    public const string DPOP_OFF = 'off';
    public const string DPOP_OPTIONAL = 'optional';
    public const string DPOP_REQUIRED = 'required';

    /** @var list<string> */
    public array $trustedClients;
    public ?string $consentUrl;
    public ?string $deviceUrl;

    /**
     * @param string|null $consentUrl the host's consent page; the browser is sent there with `?request=`. Null: the authorization endpoint answers JSON only.
     * @param string|null $deviceUrl the host's device page (`verification_uri`); null turns the device flow off.
     * @param int $pollInterval seconds between a device's or a backchannel client's polls; zero turns the throttle off
     * @param array<string, string> $scopes extra scopes a host defines (name => description), beyond the permission names and the OpenID ones
     * @param list<string> $trustedClients client ids whose users are not asked for consent
     */
    public function __construct(
        ?string $consentUrl = null,
        ?string $deviceUrl = null,
        public int $accessTokenTtl = 3600,
        public int $refreshTokenTtl = 2592000,
        public int $codeTtl = 600,
        public int $deviceCodeTtl = 1800,
        public int $pollInterval = 5,
        public int $cibaTtl = 600,
        public bool $dynamicRegistration = false,
        public bool $clientIdMetadata = true,
        public string $dpop = self::DPOP_OPTIONAL,
        public array $scopes = [],
        array $trustedClients = [],
    ) {
        foreach ([$consentUrl, $deviceUrl] as $url) {
            if ($url !== null && preg_match('~^https?://[^\s?]+$~', $url) !== 1) {
                throw new LogicException('consentUrl and deviceUrl must be absolute http(s) URLs without a query.');
            }
        }
        if (!in_array($dpop, [self::DPOP_OFF, self::DPOP_OPTIONAL, self::DPOP_REQUIRED], true)) {
            throw new LogicException('dpop must be off, optional or required.');
        }
        foreach ([$accessTokenTtl, $refreshTokenTtl, $codeTtl, $deviceCodeTtl, $cibaTtl] as $seconds) {
            if ($seconds < 1) {
                throw new LogicException('Every lifetime must be at least one second.');
            }
        }
        if ($pollInterval < 0) {
            throw new LogicException('pollInterval is zero (no throttle) or more.');
        }
        foreach ($scopes as $name => $description) {
            if (preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', (string) $name) !== 1) {
                throw new LogicException('A scope name is one or more printable characters without a space, a quote or a backslash (RFC 6749 §3.3).');
            }
        }
        $this->consentUrl = $consentUrl === null ? null : rtrim($consentUrl, '/');
        $this->deviceUrl = $deviceUrl === null ? null : rtrim($deviceUrl, '/');
        $this->trustedClients = $trustedClients;
    }
}
