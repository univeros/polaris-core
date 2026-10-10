<?php

declare(strict_types=1);

namespace Polaris\Token;

use Polaris\Contract\TokenConfigurationInterface;
use Polaris\Contract\TokenInterface;
use Polaris\Contract\TokenParserInterface;
use Polaris\Exception\InvalidTokenException;
use Polaris\Token\LcobucciTokenParser;
use Override;
use Psr\Clock\ClockInterface;

use function base64_decode;
use function explode;
use function is_array;
use function is_string;
use function json_decode;
use function strtoupper;
use function strtr;

/**
 * Parses and validates access tokens, delegating signature/issuer/audience/time checks
 * to the framework {@see LcobucciTokenParser}, then enforcing two Polaris-specific rules:
 *
 * 1. A general access token must NOT carry a `purpose` claim. Single-purpose JWTs (the
 *    `mfa_token` and `step_up` tickets) are signed by the same key and would otherwise
 *    pass generic validation; rejecting any token bearing a `purpose` claim stops them
 *    from authenticating normal routes (see `docs/auth/flows.md`).
 * 2. The time claims `exp` and `iat` must be present. The framework's `LooseValidAt`
 *    constraint treats a missing `exp` as "never expires" and a missing `iat` as valid,
 *    so requiring them here closes that bypass for tokens this service accepts.
 */
final class PolarisTokenParser implements TokenParserInterface
{
    /** Time claims an access token must carry (defence against missing-claim bypass). */
    private const array REQUIRED_TIME_CLAIMS = ['iat', 'exp'];

    private readonly LcobucciTokenParser $delegate;

    public function __construct(private readonly TokenConfigurationInterface $config, ?ClockInterface $clock = null)
    {
        $this->delegate = new LcobucciTokenParser($config, $clock);
    }

    /**
     * @inheritDoc
     *
     * @throws InvalidTokenException
     */
    #[Override]
    public function parse(string $token): TokenInterface
    {
        $parsed = $this->delegate->parse($token);

        // Any `purpose` claim (of any type) marks a single-purpose ticket, not an access token.
        if ($parsed->getMetadata('purpose') !== null) {
            throw new InvalidTokenException('A single-purpose token cannot be used as an access token.');
        }

        // A JWT this server signed for another purpose (an OAuth access token `at+jwt`, an ID token, a
        // DPoP proof) is not a session: the header's `typ` must be JWT, and a token may name an
        // audience only when the server is configured with one (program 4, decision #3).
        $typ = self::typ($token);
        if ($typ !== null && strtoupper($typ) !== 'JWT') {
            throw new InvalidTokenException('A ' . $typ . ' token cannot be used as an access token.');
        }
        $audience = $this->config->getAudience();
        if (($audience === null || $audience === '') && $parsed->getMetadata('aud') !== null) {
            throw new InvalidTokenException('A token for an audience cannot be used as an access token here.');
        }

        foreach (self::REQUIRED_TIME_CLAIMS as $claim) {
            if ($parsed->getMetadata($claim) === null) {
                throw new InvalidTokenException("Access token is missing the required '$claim' claim.");
            }
        }

        return $parsed;
    }

    /**
     * The `typ` of a JWT's header, read without verifying it; null when absent or unreadable.
     */
    private static function typ(string $token): ?string
    {
        $segments = explode('.', $token);
        $decoded = base64_decode(strtr($segments[0], '-_', '+/'), true);
        $header = $decoded === false ? null : json_decode($decoded, true);
        $typ = is_array($header) ? ($header['typ'] ?? null) : null;

        return is_string($typ) && $typ !== '' ? $typ : null;
    }
}
