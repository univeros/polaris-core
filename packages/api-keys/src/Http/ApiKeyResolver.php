<?php

declare(strict_types=1);

namespace Polaris\ApiKeys\Http;

use Override;
use Polaris\ApiKeys\Keys;
use Polaris\ApiKeys\Model\ApiKey;
use Polaris\Authorization\Gate;
use Polaris\Contract\BearerResolver;
use Polaris\Contract\TokenInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Token\Token;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;

use function preg_match;
use function str_starts_with;
use function trim;

/**
 * Authenticates `Authorization: Bearer pk_...` or `x-api-key: pk_...` on core's bearer routes as the
 * key's subject (its owner, or the member who created an organization's key) in the key's organization,
 * with the key's permissions as the delegated authority ({@see Gate::DELEGATED}), so core's step-up,
 * denylist, rate-limit and authorization layers apply as to a session. A key that is unknown, revoked,
 * expired or past its rotation grace, or whose subject is gone or disabled, is refused.
 */
final class ApiKeyResolver implements BearerResolver
{
    public const string HEADER = 'x-api-key';
    public const string CLAIM = 'api_key';
    public const string RATE_LIMIT_CLAIM = 'api_key_rate_limit';
    public const string AMR = 'api_key';

    public function __construct(private readonly Keys $keys, private readonly UserRepository $users, private readonly ClockInterface $clock)
    {
    }

    #[Override]
    public function resolve(ServerRequestInterface $request): ?TokenInterface
    {
        $secret = self::presented($request);
        if ($secret === null) {
            return null;
        }
        $key = $this->keys->authenticate($secret);
        if ($key === null) {
            throw new AuthorizationTokenException('The API key is unknown, revoked or expired.');
        }
        $user = $this->users->find($key->subject());
        if (!$user instanceof User || $user->status !== User::STATUS_ACTIVE) {
            throw new AuthorizationTokenException('The API key\'s subject cannot sign in.');
        }

        return new Token($secret, $this->claims($key, $user));
    }

    /**
     * The secret the request carries, or null when it carries none of this kind.
     */
    public static function presented(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine(self::HEADER);
        if ($header === '') {
            $authorization = $request->getHeaderLine('Authorization');
            if (preg_match('/^Bearer\s+(\S.*)$/i', $authorization, $matches) !== 1) {
                return null;
            }
            $header = $matches[1];
        }
        $secret = trim($header);

        return str_starts_with($secret, 'pk_') ? $secret : null;
    }

    /**
     * @return array<string, mixed>
     */
    private function claims(ApiKey $key, User $user): array
    {
        $now = $this->clock->now();

        return [
            'sub' => $user->id,
            'org' => $key->organizationId,
            'jti' => $key->id,
            'iat' => $now,
            'exp' => $key->expiresAt ?? $now->modify('+1 hour'),
            'roles' => [],
            'email_verified' => $user->emailVerifiedAt !== null,
            'mfa' => false,
            'amr' => [self::AMR],
            self::CLAIM => $key->id,
            self::RATE_LIMIT_CLAIM => $key->rateLimit(),
            Gate::DELEGATED => $key->permissions,
        ];
    }
}
