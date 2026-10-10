<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Polaris\Config\Secrets;
use Polaris\Contract\TokenConfigurationInterface;
use Psr\Clock\ClockInterface;

use function base64_decode;
use function base64_encode;
use function hash;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function rtrim;
use function strtr;
use function explode;
use function substr_count;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * Mints and verifies the JWTs the provider issues (access tokens `at+jwt`, ID tokens) with core's own
 * signing key and `kid`, so `/auth/.well-known/jwks.json` verifies them unchanged, and offers the
 * base64url and JWK thumbprint (RFC 7638) helpers the protocol needs.
 */
final class Jwt
{
    private const int LEEWAY = 60;

    public function __construct(
        private readonly TokenConfigurationInterface $config,
        private readonly Secrets $secrets,
        private readonly ClockInterface $clock,
    ) {
    }

    public function issuer(): string
    {
        return $this->config->getIssuer();
    }

    /**
     * A signed JWT: `iss`, `iat` and `nbf` are the server's; `exp`, `sub`, `jti`, `aud` and the rest
     * come from `$claims`.
     *
     * @param array<string, mixed> $claims
     * @param array<string, string> $headers `typ` and others; `kid` and `alg` are the server's
     */
    public function mint(array $claims, DateTimeImmutable $expiresAt, array $headers = []): string
    {
        $privateKey = (string) $this->config->getPrivateKey();
        $configuration = Configuration::forAsymmetricSigner($this->config->getSigner(), InMemory::plainText($privateKey), InMemory::plainText($this->config->getPublicKey()));
        $now = $this->clock->now();
        $builder = $configuration->builder()
            ->issuedBy($this->config->getIssuer())
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($expiresAt)
            ->withHeader('kid', $this->secrets->jwtKid);
        foreach ($headers as $name => $value) {
            $builder = $builder->withHeader($name, $value);
        }
        foreach ($claims as $name => $value) {
            $builder = match ($name) {
                'sub' => $builder->relatedTo((string) $value),
                'jti' => $builder->identifiedBy((string) $value),
                'aud' => $builder->permittedFor(...(is_array($value) ? $value : [(string) $value])),
                'iss', 'iat', 'nbf', 'exp' => $builder,
                default => $builder->withClaim($name, $value),
            };
        }

        return $builder->getToken($configuration->signer(), $configuration->signingKey())->toString();
    }

    /**
     * The claims of a JWT this server signed (the current key, or the previous one during a rotation,
     * by `kid`), issued by it and valid now; `$typ` must match the header when given.
     *
     * @return array{headers: array<string, mixed>, claims: array<string, mixed>}
     * @throws OAuthException `invalid_token`
     */
    public function verify(string $jwt, ?string $typ = null): array
    {
        $publicKey = $this->config->getPublicKey();
        $parsed = $this->parse($jwt);
        $kid = $parsed->headers()->get('kid');
        if (is_string($kid) && $kid === $this->secrets->jwtPreviousKid && $this->secrets->jwtPreviousPublicKey !== null) {
            $publicKey = $this->secrets->jwtPreviousPublicKey;
        } elseif ($kid !== null && $kid !== $this->secrets->jwtKid) {
            throw new OAuthException(OAuthException::INVALID_TOKEN, 'The token names an unknown signing key.', 401);
        }
        if ($typ !== null && $parsed->headers()->get('typ') !== $typ) {
            throw new OAuthException(OAuthException::INVALID_TOKEN, 'The token is not a ' . $typ . '.', 401);
        }
        $configuration = Configuration::forAsymmetricSigner($this->config->getSigner(), InMemory::plainText($publicKey), InMemory::plainText($publicKey));
        try {
            $configuration->validator()->assert(
                $parsed,
                new SignedWith($this->config->getSigner(), $configuration->verificationKey()),
                new IssuedBy($this->config->getIssuer()),
                new LooseValidAt($this->clock, new \DateInterval('PT' . self::LEEWAY . 'S')),
            );
        } catch (RequiredConstraintsViolated $violated) {
            throw new OAuthException(OAuthException::INVALID_TOKEN, 'The token is not valid: ' . $violated->getMessage(), 401,);
        }

        return ['headers' => $parsed->headers()->all(), 'claims' => $parsed->claims()->all()];
    }

    /**
     * The decoded header of a JWT, without verifying it: enough to tell an access token (`typ`) from
     * a session token before deciding who verifies it. Null for anything that is not a JWT.
     *
     * @return array<string, mixed>|null
     */
    public static function header(string $jwt): ?array
    {
        if (substr_count($jwt, '.') !== 2) {
            return null;
        }
        $decoded = json_decode(self::base64UrlDecode(explode('.', $jwt)[0]), true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * The RFC 7638 thumbprint of a public JWK (SHA-256, base64url).
     *
     * @param array<string, mixed> $jwk
     * @throws OAuthException
     */
    public static function thumbprint(array $jwk): string
    {
        $kty = $jwk['kty'] ?? null;
        $members = match ($kty) {
            'RSA' => ['e', 'kty', 'n'],
            'EC' => ['crv', 'kty', 'x', 'y'],
            'OKP' => ['crv', 'kty', 'x'],
            default => throw new OAuthException(OAuthException::INVALID_DPOP_PROOF, 'The key type is not supported.'),
        };
        $canonical = [];
        foreach ($members as $member) {
            if (!is_string($jwk[$member] ?? null)) {
                throw new OAuthException(OAuthException::INVALID_DPOP_PROOF, 'The key is missing ' . $member . '.');
            }
            $canonical[$member] = $jwk[$member];
        }

        return self::base64UrlEncode(hash('sha256', json_encode($canonical, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), true));
    }

    public static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $encoded): string
    {
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);

        return $decoded === false ? '' : $decoded;
    }

    /**
     * @param list<string> $algorithms
     */
    public static function supportsAlgorithm(?string $algorithm, array $algorithms): bool
    {
        return is_string($algorithm) && in_array($algorithm, $algorithms, true);
    }

    private function parse(string $jwt): UnencryptedToken
    {
        try {
            $parsed = (new Parser(new JoseEncoder()))->parse($jwt);
        } catch (CannotDecodeContent | InvalidTokenStructure | UnsupportedHeaderFound) {
            throw new OAuthException(OAuthException::INVALID_TOKEN, 'The token could not be parsed.', 401);
        }
        if (!$parsed instanceof UnencryptedToken) {
            throw new OAuthException(OAuthException::INVALID_TOKEN, 'The token could not be parsed.', 401);
        }

        return $parsed;
    }
}
