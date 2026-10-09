<?php

declare(strict_types=1);

namespace Polaris\Passkey;

use LogicException;

use function in_array;
use function parse_url;
use function preg_match;
use function rtrim;

use const PHP_URL_HOST;
use const PHP_URL_SCHEME;

/**
 * The plugin's configuration: the relying party (its id is the domain the passkeys are bound to, its
 * name what the authenticator shows), the origins a ceremony may come from, whether a passkey also
 * becomes a core MFA factor, and the ceremony parameters.
 */
final readonly class Settings
{
    public const string UV_REQUIRED = 'required';
    public const string UV_PREFERRED = 'preferred';
    public const string UV_DISCOURAGED = 'discouraged';

    /** @var list<string> */
    public array $origins;
    /** The domain the passkeys are bound to. */
    public string $rpId;

    /**
     * @param list<string> $origins exact origins (`https://app.example.com`), the first's host is the rpId by default
     * @param string|null $attachment `platform`, `cross-platform` or null for no preference
     */
    public function __construct(
        array $origins,
        ?string $rpId = null,
        public string $rpName = 'Polaris',
        public bool $mfaFactor = true,
        public string $userVerification = self::UV_PREFERRED,
        public ?string $attachment = null,
        public int $timeout = 60000,
        public int $challengeTtl = 300,
    ) {
        $normalized = [];
        foreach ($origins as $origin) {
            if (preg_match('#^https?://[^/]+$#', rtrim($origin, '/')) !== 1) {
                throw new LogicException('origins must be absolute http(s) origins without a path, such as https://app.example.com.');
            }
            $origin = rtrim($origin, '/');
            if (parse_url($origin, PHP_URL_SCHEME) === 'http' && !in_array(parse_url($origin, PHP_URL_HOST), ['localhost', '127.0.0.1'], true)) {
                throw new LogicException('A plain-http origin is accepted on localhost only; passkeys need https elsewhere.');
            }
            $normalized[] = $origin;
        }
        if ($normalized === []) {
            throw new LogicException('At least one origin is required.');
        }
        if (!in_array($userVerification, [self::UV_REQUIRED, self::UV_PREFERRED, self::UV_DISCOURAGED], true)) {
            throw new LogicException('userVerification must be required, preferred or discouraged.');
        }
        if ($attachment !== null && !in_array($attachment, ['platform', 'cross-platform'], true)) {
            throw new LogicException('attachment must be platform, cross-platform or null.');
        }
        $this->origins = $normalized;
        $this->rpId = $rpId ?? (string) parse_url($normalized[0], PHP_URL_HOST);
    }

    /**
     * The hosts of the plain-http origins (development on localhost), which the library must accept.
     *
     * @return list<string>
     */
    public function insecureHosts(): array
    {
        $hosts = [];
        foreach ($this->origins as $origin) {
            if (parse_url($origin, PHP_URL_SCHEME) === 'http') {
                $hosts[] = (string) parse_url($origin, PHP_URL_HOST);
            }
        }

        return $hosts;
    }
}
