<?php

declare(strict_types=1);

namespace Polaris\Laravel\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Override;
use Polaris\Contract\TokenInterface;
use Polaris\Model\User;

/**
 * What `Auth::guard('polaris')->user()` returns: the Polaris user and the verified access token, whose
 * claims carry the active organization, roles and permissions (`claim('org')`, `claim('roles')`, ...).
 */
final readonly class PolarisUser implements Authenticatable
{
    public function __construct(public User $user, public TokenInterface $token)
    {
    }

    public function claim(string $name): mixed
    {
        return $this->token->getMetadata($name);
    }

    #[Override]
    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    #[Override]
    public function getAuthIdentifier(): string
    {
        return $this->user->id;
    }

    #[Override]
    public function getAuthPasswordName(): string
    {
        return 'password_hash';
    }

    #[Override]
    public function getAuthPassword(): string
    {
        return (string) $this->user->passwordHash;
    }

    #[Override]
    public function getRememberToken(): ?string
    {
        return null;
    }

    #[Override]
    public function setRememberToken($value): void
    {
    }

    #[Override]
    public function getRememberTokenName(): string
    {
        return '';
    }
}
