<?php

declare(strict_types=1);

namespace Polaris\Symfony\Security;

use Override;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Wiring\Graph;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

use function is_string;
use function preg_match;
use function trim;

/**
 * The authenticator for the application's own firewalls (`custom_authenticators: [Polaris\Symfony\Security\PolarisAuthenticator]`):
 * a valid `Authorization: Bearer` access token, verified by the Polaris token factory, authenticates a
 * {@see PolarisUser}. Nothing else authenticates through it: login is the endpoints' job. As the
 * firewall's entry point it answers 401 with a `WWW-Authenticate: Bearer` challenge.
 */
final class PolarisAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    public function __construct(private readonly Graph $graph)
    {
    }

    #[Override]
    public function supports(Request $request): bool
    {
        return self::bearer($request) !== null;
    }

    #[Override]
    public function authenticate(Request $request): Passport
    {
        try {
            $token = $this->graph->tokenFactory()->fromTokenString((string) self::bearer($request));
        } catch (AuthorizationTokenException) {
            throw new CustomUserMessageAuthenticationException('The access token is invalid.');
        }
        $subject = $token->getMetadata('sub');
        if (!is_string($subject) || $subject === '') {
            throw new CustomUserMessageAuthenticationException('The access token has no subject.');
        }

        return new SelfValidatingPassport(new UserBadge($subject, function () use ($subject, $token): PolarisUser {
            $user = $this->graph->users()->find($subject);
            if ($user === null) {
                throw new UserNotFoundException();
            }

            return new PolarisUser($user, $token);
        }));
    }

    #[Override]
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    #[Override]
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return self::unauthorized();
    }

    #[Override]
    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return self::unauthorized();
    }

    private static function unauthorized(): JsonResponse
    {
        return new JsonResponse(['error' => 'unauthorized', 'message' => 'Authentication is required.'], 401, ['WWW-Authenticate' => 'Bearer']);
    }

    private static function bearer(Request $request): ?string
    {
        $header = (string) $request->headers->get('Authorization', '');

        return preg_match('/^Bearer\s+(\S.*)$/i', $header, $matches) === 1 ? trim($matches[1]) : null;
    }
}
