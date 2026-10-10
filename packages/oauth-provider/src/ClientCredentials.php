<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use SensitiveParameter;

use function base64_decode;
use function explode;
use function is_string;
use function preg_match;
use function str_contains;
use function urldecode;

/**
 * How a request identifies its client at the token, introspection, revocation, device and CIBA
 * endpoints: `client_id` and `client_secret` in the body (`client_secret_post`), HTTP Basic
 * (`client_secret_basic`), a signed assertion (`private_key_jwt`), or `client_id` alone (`none`).
 */
final readonly class ClientCredentials
{
    public const string ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    public function __construct(
        public ?string $clientId,
        #[SensitiveParameter] public ?string $secret,
        public bool $basic,
        public ?string $assertion,
        public ?string $assertionType,
    ) {
    }

    /**
     * @param array<string, mixed> $body the parsed body (or query) parameters
     */
    public static function from(array $body, ?string $authorizationHeader): self
    {
        $clientId = self::text($body['client_id'] ?? null);
        $secret = self::text($body['client_secret'] ?? null);
        $basic = false;
        if (is_string($authorizationHeader) && preg_match('/^Basic\s+(\S+)$/i', $authorizationHeader, $matches) === 1) {
            $decoded = base64_decode($matches[1], true);
            if ($decoded !== false && str_contains($decoded, ':')) {
                [$user, $password] = explode(':', $decoded, 2);
                $clientId = urldecode($user);
                $secret = urldecode($password);
                $basic = true;
            }
        }

        return new self($clientId, $secret, $basic, self::text($body['client_assertion'] ?? null), self::text($body['client_assertion_type'] ?? null));
    }

    private static function text(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
