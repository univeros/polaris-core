<?php

declare(strict_types=1);

namespace Polaris\Passwordless;

use Polaris\Identity\EmailNormalizer;
use Polaris\Messaging\Message;
use Polaris\Messaging\Sender;
use Polaris\Model\User;
use Polaris\Passwordless\Model\Secret;
use Polaris\Repository\UserRepository;
use Polaris\Token\ClientContext;

use function in_array;
use function is_string;
use function str_contains;
use function urlencode;

/**
 * Magic links: an email with a link to `/magic-link/verify`, valid once for 15 minutes; the verify opens
 * the session and redirects to the application with a one-minute code for `/magic-link/exchange`, so
 * tokens never travel in a URL.
 */
final class MagicLinks
{
    public const string AMR = 'magic_link';

    public function __construct(
        private readonly Settings $settings,
        private readonly SecretStore $secrets,
        private readonly Sessions $sessions,
        private readonly Sender $sender,
        private readonly UserRepository $users,
    ) {
    }

    /**
     * Sends a link when the email belongs to an active user, or to nobody and sign-up is on; the caller
     * answers the same either way.
     *
     * @throws PasswordlessException the redirect URI is not one of the configured ones
     */
    public function send(string $email, ?string $redirectUri): void
    {
        $redirectUri = $this->redirectUri($redirectUri);
        $email = EmailNormalizer::normalize($email);
        $user = $this->users->findOneBy(['email' => $email]);
        if ($user instanceof User ? $user->status === User::STATUS_DISABLED : !$this->settings->signUp) {
            return;
        }
        $token = SecretStore::token();
        $this->secrets->issueToken(Secret::MAGIC_LINK, $email, $user?->id, $token, $this->settings->magicLinkTtl, ['email' => $email, 'redirect_uri' => $redirectUri]);
        $link = $this->settings->baseUrl . '/magic-link/verify?token=' . urlencode($token);
        $this->sender->send(Message::EMAIL, $email, 'email.magic_link', ['link' => $link, 'ttl' => $this->settings->magicLinkTtl], essential: true);
    }

    /**
     * Spends the link's token and opens the session; the application URL to redirect to, with the code.
     *
     * @throws PasswordlessException the token is unknown, used or expired; the account is disabled
     */
    public function verify(string $token, ClientContext $client): string
    {
        $secret = $this->secrets->spendToken(Secret::MAGIC_LINK, $token);
        $email = $secret?->data['email'] ?? null;
        $redirectUri = $secret?->data['redirect_uri'] ?? null;
        if (!is_string($email) || !is_string($redirectUri)) {
            throw PasswordlessException::tokenInvalid();
        }
        $envelope = $this->sessions->open($this->sessions->forEmail($email), [self::AMR], $client);
        $code = $this->sessions->handOff($envelope);

        return $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . 'code=' . $code;
    }

    /**
     * @throws PasswordlessException
     */
    private function redirectUri(?string $requested): string
    {
        $allowed = $this->settings->redirectUris;
        if ($requested === null || $requested === '') {
            return $allowed[0] ?? throw new PasswordlessException(PasswordlessException::REDIRECT_NOT_ALLOWED, 'No redirect_uri is configured; pass one of the allowed ones.');
        }
        if (!in_array($requested, $allowed, true)) {
            throw new PasswordlessException(PasswordlessException::REDIRECT_NOT_ALLOWED, 'redirect_uri is not one of the allowed ones.');
        }

        return $requested;
    }
}
