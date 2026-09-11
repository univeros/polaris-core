<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use LogicException;
use Override;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Cli\CommandProvider;
use Polaris\Contract\BreachedPasswordCheckInterface;
use Polaris\Messaging\Suppressor;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Sentinel\Console\ListsCommand;
use Polaris\Sentinel\Http\ResponseFactories;
use Polaris\Sentinel\Http\SentinelMiddleware;
use Polaris\Sentinel\Provider\BotVerifier;
use Polaris\Sentinel\Provider\BreachChecker;
use Polaris\Sentinel\Provider\DomainList;
use Polaris\Sentinel\Provider\FileDomainList;
use Polaris\Sentinel\Provider\GeoResolver;
use Polaris\Sentinel\Provider\NullResolver;
use Polaris\Sentinel\Signal\Bot;
use Polaris\Sentinel\Signal\BreachedPassword;
use Polaris\Sentinel\Signal\CredentialStuffing;
use Polaris\Sentinel\Signal\DeviceSignal;
use Polaris\Sentinel\Signal\DisposableEmail;
use Polaris\Sentinel\Signal\ImpossibleTravel;
use Polaris\Sentinel\Signal\IpList;
use Polaris\Sentinel\Signal\Velocity;
use Polaris\Wiring\Graph;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseFactoryInterface;

use function dirname;

/**
 * The sentinel plugin: `new SentinelPlugin(mode: 'observe')` in `Config::$plugins`, after `AuditPlugin`
 * and `AdminPlugin`. Its middleware judges sign-ups, sign-ins, password resets and code sends with the
 * local signals (velocity, credential stuffing, IP rules, devices, disposable domains, and, when a
 * provider is configured, captcha, impossible travel and breached passwords); the policy allows,
 * challenges or blocks; `observe` records without enforcing; a challenge is answered only when a captcha
 * verifier can verify the retry. Every decision where a signal spoke is a `sentinel.evaluated` event and a
 * row for `GET /admin/sentinel/decisions`; the operators manage IP rules and clear counters under
 * `/admin/sentinel` with `polaris/admin`'s principals.
 */
final class SentinelPlugin extends AbstractPlugin implements CommandProvider
{
    public const string ID = 'sentinel';
    public const string OBSERVE = 'observe';
    public const string ENFORCE = 'enforce';

    /**
     * @param list<Signal> $signals the application's own signals, after the built-in ones
     * @param array<string, array{int, int}> $velocity dimension => [limit, window seconds]
     * @param list<string> $disposableDomains domains beside the bundled list
     * @param array<string, string> $routes path => attempt kind, the guarded routes
     */
    public function __construct(
        private readonly string $mode = self::OBSERVE,
        private readonly Policy $policy = new Policy(),
        private readonly array $signals = [],
        private readonly bool $builtIn = true,
        private readonly array $velocity = ['ip' => [20, 600], 'email' => [10, 600], 'device' => [30, 600]],
        private readonly ?BotVerifier $verifier = null,
        private readonly ?GeoResolver $geo = null,
        private readonly ?BreachChecker $breachChecker = null,
        private readonly ?DomainList $domains = null,
        private readonly array $disposableDomains = [],
        private readonly ?string $disposableListFile = null,
        private readonly ?CounterStore $counters = null,
        private readonly ?ResponseFactoryInterface $responses = null,
        private readonly array $routes = SentinelMiddleware::ROUTES,
        private readonly ?ClientInterface $httpClient = null,
        private readonly ?RequestFactoryInterface $requestFactory = null,
    ) {
        if ($mode !== self::OBSERVE && $mode !== self::ENFORCE) {
            throw new LogicException('mode must be "observe" or "enforce".');
        }
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The sentinel plugin is not registered.');
        }

        return $plugin;
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
        $services = [
            CounterStore::class => fn(Graph $graph): CounterStore => $this->counters ?? new CacheCounterStore($graph->cache(), $graph->clock()),
            Decisions::class => static fn(Graph $graph): Decisions => new Decisions($graph->database(), $graph->clock()),
            Devices::class => static fn(Graph $graph): Devices => new Devices($graph->database(), $graph->clock()),
            IpRules::class => static fn(Graph $graph): IpRules => new IpRules($graph->database(), $graph->clock()),
            GeoResolver::class => fn(): GeoResolver => $this->geo ?? new NullResolver(),
            DomainList::class => fn(): DomainList => $this->domains ?? new FileDomainList($this->disposableListFile, $this->disposableDomains),
            Engine::class => fn(Graph $graph): Engine => new Engine($this->signals($graph), $this->policy, $this->mode === self::ENFORCE, $graph->get(Decisions::class), $graph->events(), $graph->logger()),
            Listener::class => static fn(Graph $graph): Listener => new Listener($graph->get(Engine::class), $graph->get(Devices::class), $graph->get(GeoResolver::class)),
            Suppressor::class => static fn(Graph $graph): Suppressor => new QuietMode($graph->get(Decisions::class), $graph->clock()),
        ];
        if ($this->breachChecker !== null) {
            $services[BreachedPasswordCheckInterface::class] = fn(): BreachedPasswordCheckInterface => new BreachCheckPort($this->breachChecker);
        }

        return $services;
    }

    #[Override]
    public function listeners(Graph $graph): array
    {
        self::catalog($graph);

        return [$graph->get(Listener::class)];
    }

    #[Override]
    public function middleware(Graph $graph): array
    {
        self::catalog($graph);

        return [new SentinelMiddleware($graph->get(Engine::class), $this->responses ?? ResponseFactories::discover(), $this->verifier !== null, $this->routes)];
    }

    #[Override]
    public function commands(Graph $graph): array
    {
        return [new ListsCommand($this->httpClient, $this->requestFactory, $this->disposableListFile ?? FileDomainList::bundledFile())];
    }

    public function mode(): string
    {
        return $this->mode;
    }

    /**
     * The `sentinel.*` names join the audit catalog: the audit plugin must be registered.
     */
    public static function catalog(Graph $graph): Catalog
    {
        AuditPlugin::of($graph);
        $catalog = $graph->get(Catalog::class);
        $catalog->extend(AuditNames::ALL);

        return $catalog;
    }

    /**
     * @return list<Signal>
     */
    private function signals(Graph $graph): array
    {
        if (!$this->builtIn) {
            return $this->signals;
        }
        $signals = [
            new IpList($graph->get(IpRules::class)),
            new Velocity($graph->get(CounterStore::class), $this->velocity),
            new CredentialStuffing($graph->get(CounterStore::class), $graph->cache()),
            new DisposableEmail($graph->get(DomainList::class)),
            new DeviceSignal($graph->get(Devices::class), $graph->users()),
        ];
        if ($this->verifier !== null) {
            $signals[] = new Bot($this->verifier);
        }
        if ($this->geo !== null) {
            $signals[] = new ImpossibleTravel($this->geo, $graph->get(Devices::class), $graph->users(), $graph->clock());
        }
        if ($this->breachChecker !== null) {
            $signals[] = new BreachedPassword($this->breachChecker);
        }

        return [...$signals, ...$this->signals];
    }
}
