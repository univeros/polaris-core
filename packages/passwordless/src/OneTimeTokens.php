<?php

declare(strict_types=1);

namespace Polaris\Passwordless;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\TokenInterface;
use Polaris\Model\User;
use Polaris\Passwordless\Model\Secret;
use Polaris\Repository\UserRepository;
use Polaris\Token\ClientContext;
use SensitiveParameter;

use function array_values;
use function array_filter;
use function is_array;
use function is_bool;
use function is_int;
use function is_string;

/**
 * One-time tokens: a signed-in session hands itself to another device or domain. The token lives three
 * minutes and opens a new session that inherits how the first one authenticated (amr, mfa, auth_time)
 * and its organization; it skips the MFA gate, which the first session already passed. Only a live
 * session may generate one (an access token without `sid`, an impersonation, cannot), and the token dies
 * with it: a session ended before the verify transfers nothing.
 */
final class OneTimeTokens
{
    public function __construct(
        private readonly Settings $settings,
        private readonly SecretStore $secrets,
        private readonly Sessions $sessions,
        private readonly UserRepository $users,
        private readonly DatabaseAdapter $database,
    ) {
    }

    /**
     * @return array{token: string, expires_in: int}
     * @throws PasswordlessException the token has no live session behind it
     */
    public function generate(TokenInterface $token): array
    {
        $userId = (string) $token->getMetadata('sub');
        $sessionId = $token->getMetadata('sid');
        if (!is_string($sessionId) || $sessionId === '' || $this->database->findOne('auth_refresh_tokens', ['family_id' => $sessionId, 'revoked_at' => null]) === null) {
            throw new PasswordlessException(PasswordlessException::SESSION_REQUIRED, 'A one-time token needs a live session.');
        }
        $amr = $token->getMetadata('amr');
        $org = $token->getMetadata('org');
        $authTime = $token->getMetadata('auth_time');
        $mfa = $token->getMetadata('mfa');
        $value = SecretStore::token();
        $this->secrets->issueToken(Secret::ONE_TIME_TOKEN, $userId, $userId, $value, $this->settings->oneTimeTokenTtl, [
            'amr' => is_array($amr) ? array_values(array_filter($amr, 'is_string')) : [],
            'org' => is_string($org) && $org !== '' ? $org : null,
            'auth_time' => is_int($authTime) ? $authTime : null,
            'mfa' => is_bool($mfa) && $mfa,
            'sid' => $sessionId,
        ]);

        return ['token' => $value, 'expires_in' => $this->settings->oneTimeTokenTtl];
    }

    /**
     * @return array<string, mixed> the envelope's `data`
     * @throws PasswordlessException
     */
    public function verify(#[SensitiveParameter] string $value, ClientContext $client): array
    {
        $secret = $this->secrets->spendToken(Secret::ONE_TIME_TOKEN, $value);
        $user = $secret?->userId === null ? null : $this->users->find($secret->userId);
        $sessionId = $secret?->data['sid'] ?? null;
        if ($secret === null || !$user instanceof User || !is_string($sessionId) || $this->database->findOne('auth_refresh_tokens', ['family_id' => $sessionId, 'revoked_at' => null]) === null) {
            throw PasswordlessException::tokenInvalid();
        }
        $amr = $secret->data['amr'] ?? [];
        $org = $secret->data['org'] ?? null;
        $authTime = $secret->data['auth_time'] ?? null;

        return $this->sessions->open(
            $user,
            is_array($amr) && $amr !== [] ? array_values(array_filter($amr, 'is_string')) : ['one_time_token'],
            $client,
            gate: false,
            organizationId: is_string($org) ? $org : null,
            mfa: ($secret->data['mfa'] ?? false) === true,
            authTime: is_int($authTime) ? $authTime : null,
        );
    }
}
