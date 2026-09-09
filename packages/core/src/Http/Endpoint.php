<?php

declare(strict_types=1);

namespace Polaris\Http;

use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\ResolvedAuthority;
use Polaris\Contract\TokenInterface;
use Polaris\Token\ClientContext;
use Univeros\Polaris\Http\Middleware\MfaTicket;

use function filter_var;
use function in_array;
use function is_array;
use function is_string;
use function strlen;

use const FILTER_VALIDATE_EMAIL;

/**
 * Base class of every endpoint: parse the {@see Input}, call a service, map the outcome to a
 * {@see Result}. The helpers keep the response envelopes of 1.0 byte for byte.
 */
abstract class Endpoint
{
    abstract public function __invoke(Input $input): Result;

    /**
     * @param array<string, mixed> $output
     */
    protected function respond(int $status, array $output): Result
    {
        return new Result($status, $output);
    }

    /**
     * @param list<string> $errors
     */
    protected function unprocessable(array $errors): Result
    {
        return $this->respond(422, ['errors' => $errors]);
    }

    protected function unauthorized(): Result
    {
        return $this->respond(401, ['error' => 'unauthorized', 'message' => 'Authentication is required.']);
    }

    protected function forbidden(string $message): Result
    {
        return $this->respond(403, ['error' => 'forbidden', 'message' => $message]);
    }

    protected function notFound(string $message): Result
    {
        return $this->respond(404, ['error' => 'not_found', 'message' => $message]);
    }

    protected function client(Input $input): ClientContext
    {
        $ip = $input->attribute(Attributes::IP_ADDRESS);
        $userAgent = $input->attribute(Attributes::USER_AGENT);

        return new ClientContext(
            is_string($ip) ? $ip : null,
            is_string($userAgent) && $userAgent !== '' ? $userAgent : null,
        );
    }

    protected function isEmail(string $email): bool
    {
        return strlen($email) <= 320 && filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    protected function token(Input $input): ?TokenInterface
    {
        $token = $input->attribute(Attributes::TOKEN);

        return $token instanceof TokenInterface ? $token : null;
    }

    protected function mfaTicket(Input $input): ?MfaTicket
    {
        $ticket = $input->attribute(Attributes::MFA_TICKET);

        return $ticket instanceof MfaTicket ? $ticket : null;
    }

    protected function actorId(TokenInterface $token): string
    {
        return (string) $token->getMetadata('sub');
    }

    protected function actorOrg(TokenInterface $token): ?string
    {
        $org = $token->getMetadata('org');

        return is_string($org) && $org !== '' ? $org : null;
    }

    /**
     * True when the caller may not act on `$organizationId`: it is not the token's active org and
     * the caller is not a superadmin (by the verified authority when the authorization middleware
     * resolved one, otherwise by the token's roles claim).
     */
    protected function deniesActiveOrg(Input $input, TokenInterface $token, string $organizationId): bool
    {
        $verified = $input->attribute(Attributes::AUTHORITY);
        if ($verified instanceof ResolvedAuthority) {
            $isSuperadmin = in_array(PermissionCatalog::ROLE_SUPERADMIN, $verified->roles, true);
        } else {
            $roles = $token->getMetadata('roles');
            $isSuperadmin = is_array($roles) && in_array(PermissionCatalog::ROLE_SUPERADMIN, $roles, true);
        }

        return !$isSuperadmin && $organizationId !== $token->getMetadata('org');
    }
}
