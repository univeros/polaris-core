<?php

declare(strict_types=1);

namespace Polaris\Passkey;

use LogicException;
use Override;
use Polaris\Contract\MfaFactorTypeProvider;
use Polaris\Event\MfaFactorRemoved;
use Polaris\Event\UserDeleted;
use Polaris\Passkey\Factor\PasskeyFactorType;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;

use function dirname;

/**
 * The passkey plugin: `new PasskeyPlugin(origins: ['https://app.example.com'], rpName: 'App')` in
 * `Config::$plugins`. WebAuthn registration from a session, discoverable sign-in (conditional UI)
 * ending in core's login envelope with `amr: ["passkey"]`, naming and removal; and, by default, every
 * passkey is also a core MFA factor of type `passkey`, verified through core's own `/auth/mfa/verify`
 * and `/auth/mfa/step-up` with the assertion as the `code`.
 */
final class PasskeyPlugin extends AbstractPlugin implements MfaFactorTypeProvider
{
    public const string ID = 'passkey';

    /** The sign-in route for sentinel's `routes` option (path => attempt kind). */
    public const array SENTINEL_ROUTES = ['/passkey/authenticate/verify' => 'sign_in'];

    private readonly Settings $settings;

    /**
     * @param list<string> $origins exact origins a ceremony may come from; the first's host is the relying party id
     * @param 'platform'|'cross-platform'|null $attachment
     */
    public function __construct(
        array $origins,
        ?string $rpId = null,
        string $rpName = 'Polaris',
        bool $mfaFactor = true,
        string $userVerification = Settings::UV_PREFERRED,
        ?string $attachment = null,
        int $timeout = 60000,
        int $challengeTtl = 300,
        private readonly ?Protocol $protocol = null,
    ) {
        $this->settings = new Settings($origins, $rpId, $rpName, $mfaFactor, $userVerification, $attachment, $timeout, $challengeTtl);
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The passkey plugin is not registered.');
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
            Protocol::class => fn(): Protocol => $this->protocol ?? new WebauthnProtocol($this->settings),
            Passkeys::class => static fn(Graph $graph): Passkeys => new Passkeys($graph->database(), $graph->clock()),
            Sessions::class => static fn(Graph $graph): Sessions => new Sessions($graph->config()->auth, $graph->unitOfWork(), $graph->tokens(), $graph->principals(), $graph->mfaLogin(), $graph->events(), $graph->clock()),
            PasskeyService::class => fn(Graph $graph): PasskeyService => new PasskeyService(
                $this->settings,
                $graph->get(Protocol::class),
                $graph->get(Passkeys::class),
                $graph->get(Sessions::class),
                $graph->cache(),
                $graph->users(),
                $graph->mfaConfirmation(),
                $graph->mfaManagement(),
                $graph->clock(),
            ),
        ];
    }

    #[Override]
    public function mfaFactorTypes(Graph $graph): array
    {
        return $this->settings->mfaFactor ? [new PasskeyFactorType($graph->get(PasskeyService::class))] : [];
    }

    #[Override]
    public function listeners(Graph $graph): array
    {
        // A factor removed under core's route leaves its passkey as a sign-in credential; an erased
        // user leaves no passkey behind.
        return [static function (object $event) use ($graph): void {
            if ($event instanceof MfaFactorRemoved) {
                $graph->get(Passkeys::class)->detachFactor($event->factorId);
            }
            if ($event instanceof UserDeleted) {
                $graph->get(Passkeys::class)->deleteForUser($event->userId);
            }
        }];
    }
}
