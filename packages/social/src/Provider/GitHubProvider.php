<?php

declare(strict_types=1);

namespace Polaris\Social\Provider;

use Override;
use Polaris\Social\SocialException;

use function is_array;
use function is_string;

/**
 * GitHub: `/user` hides a private email, so the verified primary address comes from `/user/emails`
 * (the `user:email` scope); a verified address is what GitHub says it is.
 */
final class GitHubProvider extends OAuth2Provider
{
    private const string EMAILS = 'https://api.github.com/user/emails';

    #[Override]
    public function profile(Tokens $tokens, string $nonce, array $callback): Profile
    {
        $profile = parent::profile($tokens, $nonce, $callback);
        try {
            $emails = $this->http->json('GET', self::EMAILS, $tokens->accessToken, $this->definition->userinfoHeaders);
        } catch (SocialException) {
            return $profile;
        }
        $chosen = null;
        foreach ($emails as $entry) {
            if (!is_array($entry) || !is_string($entry['email'] ?? null) || ($entry['verified'] ?? false) !== true) {
                continue;
            }
            if (($entry['primary'] ?? false) === true || $chosen === null) {
                $chosen = $entry['email'];
            }
            if (($entry['primary'] ?? false) === true) {
                break;
            }
        }

        return $chosen === null ? $profile : new Profile($profile->subject, $chosen, true, $profile->name, $profile->extra);
    }
}
