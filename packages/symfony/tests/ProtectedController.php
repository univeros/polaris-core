<?php

declare(strict_types=1);

namespace Polaris\Symfony\Tests;

use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * An application route behind the Polaris authenticator: answers the authenticated user's identifier and roles.
 */
final class ProtectedController
{
    public function __construct(private readonly Security $security)
    {
    }

    public function __invoke(): JsonResponse
    {
        $user = $this->security->getUser();

        return new JsonResponse(['id' => $user?->getUserIdentifier(), 'roles' => $user?->getRoles()]);
    }
}
