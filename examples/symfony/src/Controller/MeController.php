<?php

declare(strict_types=1);

namespace PolarisDemo\Controller;

use Polaris\Symfony\Security\PolarisUser;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

/**
 * An application route behind the Polaris authenticator (config/packages/security.yaml): the firewall
 * turns a Polaris access token into a PolarisUser.
 */
final class MeController
{
    public function __construct(private readonly Security $security)
    {
    }

    #[Route('/app/me', methods: ['GET'])]
    public function __invoke(): JsonResponse
    {
        $user = $this->security->getUser();
        if (!$user instanceof PolarisUser) {
            return new JsonResponse(['error' => 'unauthorized'], 401);
        }

        return new JsonResponse(['id' => $user->user->id, 'email' => $user->user->email, 'organization' => $user->claim('org'), 'roles' => $user->getRoles()]);
    }
}
