<?php

declare(strict_types=1);

namespace Polaris\Yii\Tests;

use DateTimeImmutable;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Model\User;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\ClientContext;
use Polaris\Token\SessionPrincipal;
use Polaris\Wiring\Graph;
use Symfony\Component\Uid\Uuid;

use function str_repeat;

/**
 * What several tests need: valid secrets and settings, and a user with a live access token.
 */
final class Fixtures
{
    /** @var array{private: string, public: string}|null */
    private static ?array $keys = null;

    /**
     * @return array{private: string, public: string}
     */
    public static function keys(): array
    {
        return self::$keys ??= TestKeys::rsa();
    }

    /**
     * @return array<string, string>
     */
    public static function secretsArray(): array
    {
        return ['app_key' => str_repeat('k', 32), 'jwt_private_key' => self::keys()['private'], 'jwt_public_key' => self::keys()['public'], 'jwt_kid' => 'test'];
    }

    public static function secrets(): Secrets
    {
        return Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => self::keys()['private'], 'AUTH_JWT_PUBLIC_KEY' => self::keys()['public'], 'AUTH_JWT_KID' => 'test']);
    }

    public static function auth(): AuthConfig
    {
        return AuthConfig::fromArray(['issuer' => 'https://issuer.test']);
    }

    /**
     * @return array{id: string, token: string}
     */
    public static function userWithToken(Graph $graph): array
    {
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = 'ada@example.com';
        $user->emailVerifiedAt = new DateTimeImmutable();
        $user->createdAt = new DateTimeImmutable();
        $user->updatedAt = new DateTimeImmutable();
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();

        return ['id' => $user->id, 'token' => $graph->tokens()->issue(new SessionPrincipal($user->id, roles: ['owner'], emailVerified: true), ClientContext::none())->accessToken];
    }
}
