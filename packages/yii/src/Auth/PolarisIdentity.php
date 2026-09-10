<?php

declare(strict_types=1);

namespace Polaris\Yii\Auth;

use Override;
use Polaris\Contract\TokenInterface;
use Polaris\Model\User;
use Yiisoft\Auth\IdentityInterface;

/**
 * The identity the authentication method produces: the Polaris user and the verified access token,
 * whose claims carry the active organization, roles and permissions (`claim('org')`, `claim('roles')`).
 */
final readonly class PolarisIdentity implements IdentityInterface
{
    public function __construct(public User $user, public TokenInterface $token)
    {
    }

    public function claim(string $name): mixed
    {
        return $this->token->getMetadata($name);
    }

    #[Override]
    public function getId(): string
    {
        return $this->user->id;
    }
}
