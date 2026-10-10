<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use Polaris\Authorization\PermissionCatalog;
use Polaris\Model\User;
use Polaris\OAuth\Model\Client;

use function array_keys;
use function array_unique;
use function array_values;
use function implode;
use function in_array;
use function preg_split;
use function sprintf;
use function trim;

/**
 * Scopes are permissions: a scope is a core (or plugin) permission name, one of the OpenID ones
 * (`openid`, `profile`, `email`, `offline_access`) or an extra the host configured. The permission
 * scopes become the token's delegated authority; the OpenID ones map to claims.
 */
final class Scopes
{
    public const string OPENID = 'openid';
    public const string PROFILE = 'profile';
    public const string EMAIL = 'email';
    public const string OFFLINE_ACCESS = 'offline_access';

    public const array RESERVED = [
        self::OPENID => 'Sign in with OpenID Connect (an ID token)',
        self::PROFILE => 'Your name',
        self::EMAIL => 'Your email address and whether it is verified',
        self::OFFLINE_ACCESS => 'Access while you are away (a refresh token)',
    ];

    public function __construct(private readonly PermissionCatalog $catalog, private readonly Settings $settings)
    {
    }

    /**
     * Every scope this server knows, with its description.
     *
     * @return array<string, string>
     */
    public function all(): array
    {
        return [...self::RESERVED, ...$this->catalog->permissions(), ...$this->settings->scopes];
    }

    /**
     * The scopes a `scope` parameter names, each known to the server and allowed to the client;
     * an absent parameter means none.
     *
     * @return list<string>
     * @throws OAuthException `invalid_scope`
     */
    public function parse(?string $scope, ?Client $client = null): array
    {
        if ($scope === null || trim($scope) === '') {
            return [];
        }
        $known = $this->all();
        $scopes = [];
        foreach (preg_split('/\s+/', trim($scope)) ?: [] as $name) {
            if (!isset($known[$name])) {
                throw new OAuthException(OAuthException::INVALID_SCOPE, sprintf('Unknown scope "%s".', $name));
            }
            if ($client !== null && $client->scopes !== [] && !in_array($name, $client->scopes, true)) {
                throw new OAuthException(OAuthException::INVALID_SCOPE, sprintf('The client may not ask for "%s".', $name));
            }
            $scopes[] = $name;
        }

        return array_values(array_unique($scopes));
    }

    /**
     * `$requested` must be within `$granted` (a refresh or an exchange narrows, never widens).
     *
     * @param list<string> $requested
     * @param list<string> $granted
     * @return list<string>
     */
    public static function within(array $requested, array $granted): array
    {
        foreach ($requested as $scope) {
            if (!in_array($scope, $granted, true)) {
                throw new OAuthException(OAuthException::INVALID_SCOPE, sprintf('"%s" is beyond what was granted.', $scope));
            }
        }

        return $requested;
    }

    /**
     * @param list<string> $scopes
     */
    public static function join(array $scopes): string
    {
        return implode(' ', $scopes);
    }

    /**
     * The permission names among the scopes: what a token may do on Polaris routes.
     *
     * @param list<string> $scopes
     * @return list<string>
     */
    public function permissions(array $scopes): array
    {
        $catalog = $this->catalog->permissions();
        $permissions = [];
        foreach ($scopes as $scope) {
            if (isset($catalog[$scope])) {
                $permissions[] = $scope;
            }
        }

        return $permissions;
    }

    /**
     * The OpenID claims the scopes allow about a user.
     *
     * @param list<string> $scopes
     * @return array<string, mixed>
     */
    public static function claims(User $user, array $scopes): array
    {
        $claims = [];
        if (in_array(self::EMAIL, $scopes, true)) {
            $claims['email'] = $user->email;
            $claims['email_verified'] = $user->emailVerifiedAt !== null;
        }
        if (in_array(self::PROFILE, $scopes, true)) {
            $claims['name'] = $user->displayName;
            $claims['updated_at'] = $user->updatedAt->getTimestamp();
        }

        return $claims;
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->all());
    }
}
