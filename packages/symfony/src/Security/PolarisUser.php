<?php

declare(strict_types=1);

namespace Polaris\Symfony\Security;

use Override;
use Polaris\Contract\TokenInterface;
use Polaris\Model\User;
use Symfony\Component\Security\Core\User\UserInterface;

use function array_unique;
use function array_values;
use function is_array;
use function is_string;
use function str_replace;
use function strtoupper;

/**
 * The security user the authenticator produces: the Polaris user and the verified access token. Roles
 * are `ROLE_USER` plus one `ROLE_POLARIS_<ROLE>` per role the token carries for the active organization;
 * the claims (`claim('org')`, ...) stay available for finer checks.
 */
final readonly class PolarisUser implements UserInterface
{
    public function __construct(public User $user, public TokenInterface $token)
    {
    }

    public function claim(string $name): mixed
    {
        return $this->token->getMetadata($name);
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function getRoles(): array
    {
        $roles = ['ROLE_USER'];
        $claimed = $this->token->getMetadata('roles');
        foreach (is_array($claimed) ? $claimed : [] as $role) {
            if (is_string($role) && $role !== '') {
                $roles[] = 'ROLE_POLARIS_' . strtoupper(str_replace('-', '_', $role));
            }
        }

        return array_values(array_unique($roles));
    }

    #[Override]
    public function getUserIdentifier(): string
    {
        return $this->user->id;
    }

    /**
     * Nothing to erase: the token is the credential and it is not a secret of this object.
     */
    public function eraseCredentials(): void
    {
    }
}
