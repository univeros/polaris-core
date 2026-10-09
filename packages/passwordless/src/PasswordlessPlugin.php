<?php

declare(strict_types=1);

namespace Polaris\Passwordless;

use LogicException;
use Override;
use Polaris\Messaging\MessagingPlugin;
use Polaris\Messaging\Sender;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;

use function dirname;

/**
 * The passwordless plugin: `new PasswordlessPlugin(baseUrl: 'https://app.example.com/auth', redirectUris:
 * ['https://app.example.com/signed-in'])` in `Config::$plugins`, after `MessagingPlugin`, which sends the
 * links and codes. Four ways to sign in without a password, each ending in core's login envelope:
 * magic links, email one-time codes, phone codes (a verified second contact of an existing user) and
 * one-time tokens (a session handed to another device or domain).
 */
final class PasswordlessPlugin extends AbstractPlugin
{
    public const string ID = 'passwordless';

    /** The send and sign-in routes for sentinel's `routes` option (path => attempt kind). */
    public const array SENTINEL_ROUTES = [
        '/magic-link/send' => 'otp_send',
        '/email-otp/send' => 'otp_send',
        '/phone/send' => 'otp_send',
        '/phone/add' => 'otp_send',
        '/email-otp/verify' => 'sign_in',
        '/phone/verify' => 'sign_in',
    ];

    private readonly Settings $settings;

    /**
     * @param list<string> $redirectUris exact URLs a magic link may end on; the first is the default
     */
    public function __construct(
        string $baseUrl,
        array $redirectUris = [],
        bool $signUp = true,
        bool $respectMfa = true,
        int $magicLinkTtl = 900,
        int $otpTtl = 300,
        int $otpLength = 6,
        int $maxAttempts = 5,
        int $oneTimeTokenTtl = 180,
    ) {
        $this->settings = new Settings($baseUrl, $redirectUris, $signUp, $respectMfa, $magicLinkTtl, $otpTtl, $otpLength, $maxAttempts, $oneTimeTokenTtl);
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The passwordless plugin is not registered.');
        }

        return $plugin;
    }

    public function settings(): Settings
    {
        return $this->settings;
    }

    #[Override]
    public function id(): string
    {
        return self::ID;
    }

    #[Override]
    public function schema(): array
    {
        return Schema::models();
    }

    #[Override]
    public static function manifestDirectory(): string
    {
        return dirname(__DIR__) . '/api';
    }

    #[Override]
    public function services(): array
    {
        return [
            SecretStore::class => fn(Graph $graph): SecretStore => new SecretStore($graph->database(), $graph->pepper(), $graph->clock(), $this->settings->maxAttempts),
            Phones::class => static fn(Graph $graph): Phones => new Phones($graph->database(), $graph->clock()),
            Sessions::class => fn(Graph $graph): Sessions => new Sessions($this->settings, $graph->users(), $graph->unitOfWork(), $graph->tokens(), $graph->principals(), $graph->mfaLogin(), $graph->cache(), $graph->events(), $graph->clock()),
            MagicLinks::class => fn(Graph $graph): MagicLinks => new MagicLinks($this->settings, $graph->get(SecretStore::class), $graph->get(Sessions::class), self::sender($graph), $graph->users()),
            EmailOtp::class => fn(Graph $graph): EmailOtp => new EmailOtp($this->settings, $graph->get(SecretStore::class), $graph->get(Sessions::class), self::sender($graph), $graph->users(), $graph->unitOfWork(), $graph->passwordPolicy(), $graph->passwordHasher(), $graph->sessions(), $graph->events(), $graph->clock()),
            PhoneSignIn::class => fn(Graph $graph): PhoneSignIn => new PhoneSignIn($this->settings, $graph->get(SecretStore::class), $graph->get(Phones::class), $graph->get(Sessions::class), self::sender($graph), $graph->users()),
            OneTimeTokens::class => fn(Graph $graph): OneTimeTokens => new OneTimeTokens($this->settings, $graph->get(SecretStore::class), $graph->get(Sessions::class), $graph->users(), $graph->database()),
        ];
    }

    private static function sender(Graph $graph): Sender
    {
        MessagingPlugin::of($graph);

        return $graph->get(Sender::class);
    }
}
