<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use Override;
use Polaris\Authorization\Gate;
use Polaris\Contract\BearerResolver;
use Polaris\Contract\TokenInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Token\Token;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;

use function in_array;
use function is_array;
use function is_string;
use function preg_match;

/**
 * Authenticates the provider's own access tokens (`typ: at+jwt`) on core's bearer routes: verified
 * with core's keys, meant for this server (`aud` includes the issuer), live in the token table, and
 * presented the way they were bound (a DPoP-bound token with the `DPoP` scheme and a valid proof for
 * this request, a bearer one with `Bearer`). The request then acts as the token's user, in its
 * organization, with the permission scopes as the delegated authority ({@see Gate::DELEGATED}); a
 * client-credentials token has no user and clears no permission check.
 */
final class OAuthResolver implements BearerResolver
{
    public const string AMR = 'oauth';
    public const string CLAIM_CLIENT = 'client_id';
    public const string CLAIM_SCOPE = 'scope';
    public const string CLAIM_ACT = 'act';

    public function __construct(
        private readonly Jwt $jwt,
        private readonly Tokens $tokens,
        private readonly Scopes $scopes,
        private readonly Dpop $dpop,
        private readonly Settings $settings,
        private readonly UserRepository $users,
        private readonly ClockInterface $clock,
    ) {
    }

    #[Override]
    public function resolve(ServerRequestInterface $request): ?TokenInterface
    {
        if (preg_match('/^(Bearer|DPoP)\s+(\S+)$/i', $request->getHeaderLine('Authorization'), $matches) !== 1) {
            return null;
        }
        [, $scheme, $jwt] = $matches;
        $header = Jwt::header($jwt);
        if ($header === null || ($header['typ'] ?? null) !== Tokens::TYP) {
            return null;
        }
        try {
            $claims = $this->jwt->verify($jwt, Tokens::TYP)['claims'];
            $this->assertForThisServer($claims);
            $record = is_string($claims['jti'] ?? null) ? $this->tokens->find($claims['jti']) : null;
            if ($record === null || !$record->isLive($this->clock->now())) {
                throw new OAuthException(OAuthException::INVALID_TOKEN, 'The token is revoked or unknown.', 401);
            }
            $this->assertBinding($request, $scheme, $jwt, $record->dpopJkt);
        } catch (OAuthException $exception) {
            throw new AuthorizationTokenException($exception->description, 0, $exception);
        }
        $user = $record->userId === null ? null : $this->users->find($record->userId);
        if ($record->userId !== null && (!$user instanceof User || $user->status !== User::STATUS_ACTIVE)) {
            throw new AuthorizationTokenException('The token\'s user cannot sign in.');
        }
        $claims['iat'] = $record->createdAt;
        $claims['exp'] = $record->expiresAt;
        // The user's re-authentication is theirs, not the client's: a delegate never passes a step-up gate.
        unset($claims['auth_time']);

        return new Token($jwt, [
            ...$claims,
            'sub' => $record->userId ?? $record->clientId,
            'org' => $record->organizationId,
            'roles' => [],
            'email_verified' => $user instanceof User && $user->emailVerifiedAt !== null,
            'mfa' => false,
            'amr' => [self::AMR],
            self::CLAIM_CLIENT => $record->clientId,
            self::CLAIM_SCOPE => Scopes::join($record->scopes),
            Gate::DELEGATED => $this->scopes->permissions($record->scopes),
        ]);
    }

    /**
     * @param array<string, mixed> $claims
     * @throws OAuthException
     */
    private function assertForThisServer(array $claims): void
    {
        $aud = $claims['aud'] ?? null;
        $audiences = is_array($aud) ? $aud : [$aud];
        if (!in_array($this->jwt->issuer(), $audiences, true)) {
            throw new OAuthException(OAuthException::INVALID_TOKEN, 'The token is meant for another resource.', 401);
        }
    }

    /**
     * @throws OAuthException
     */
    private function assertBinding(ServerRequestInterface $request, string $scheme, string $jwt, ?string $boundJkt): void
    {
        $dpopScheme = preg_match('/^dpop$/i', $scheme) === 1;
        if ($boundJkt === null) {
            if ($dpopScheme) {
                throw new OAuthException(OAuthException::INVALID_TOKEN, 'A bearer token is presented with the Bearer scheme.', 401);
            }

            return;
        }
        if (!$dpopScheme || $this->settings->dpop === Settings::DPOP_OFF) {
            throw new OAuthException(OAuthException::INVALID_TOKEN, 'A DPoP-bound token is presented with the DPoP scheme and a proof.', 401);
        }
        $jkt = $this->dpop->verify($request->getHeaderLine(Dpop::HEADER), $request->getMethod(), (string) $request->getUri(), $jwt);
        if ($jkt !== $boundJkt) {
            throw new OAuthException(OAuthException::INVALID_TOKEN, 'The DPoP proof is not for the key the token is bound to.', 401);
        }
    }
}
