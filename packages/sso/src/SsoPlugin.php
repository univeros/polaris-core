<?php

declare(strict_types=1);

namespace Polaris\Sso;

use LogicException;
use Override;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Audit\Recorder;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Sso\Domain\DnsHttpsDomainVerifier;
use Polaris\Sso\Domain\DomainVerifier;
use Polaris\Sso\Oidc\HttpOidcProtocol;
use Polaris\Sso\Oidc\OidcProtocol;
use Polaris\Sso\Oidc\UnconfiguredOidc;
use Polaris\Sso\Saml\OneLoginSamlProtocol;
use Polaris\Sso\Saml\SamlProtocol;
use Polaris\Wiring\Graph;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use SensitiveParameter;

use function dirname;
use function preg_match;

/**
 * The SSO plugin: `new SsoPlugin(baseUrl: 'https://app.example.com/auth', httpClient: ..., requestFactory:
 * ..., streamFactory: ...)` in `Config::$plugins`, after `AuditPlugin` and `AdminPlugin`. Per-organization
 * SAML 2.0 and OIDC providers with verified domains, just-in-time provisioning and single logout; the
 * organizations manage their own providers under `/orgs/{id}/sso`, the operators see every provider
 * under `/admin/sso`. `baseUrl` is where Polaris is mounted (prefix included): the SP entity id, the
 * assertion consumer and single-logout URLs and the OIDC redirect URI derive from it.
 */
final class SsoPlugin extends AbstractPlugin
{
    public const string ID = 'sso';

    public function __construct(
        private readonly string $baseUrl,
        private readonly ?ClientInterface $httpClient = null,
        private readonly ?RequestFactoryInterface $requestFactory = null,
        private readonly ?StreamFactoryInterface $streamFactory = null,
        private readonly ?OidcProtocol $oidc = null,
        private readonly ?SamlProtocol $saml = null,
        private readonly ?DomainVerifier $domains = null,
        private readonly ?string $spCertificate = null,
        #[SensitiveParameter] private readonly ?string $spPrivateKey = null,
    ) {
        if (preg_match('#^https?://[^/]+#', $baseUrl) !== 1) {
            throw new LogicException('baseUrl must be an absolute http(s) URL, where Polaris is mounted.');
        }
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The sso plugin is not registered.');
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
        return [
            Sp::class => fn(): Sp => new Sp($this->baseUrl, $this->spCertificate, $this->spPrivateKey),
            Providers::class => static fn(Graph $graph): Providers => new Providers($graph->database(), $graph->encrypter(), $graph->clock()),
            Domains::class => static fn(Graph $graph): Domains => new Domains($graph->database(), $graph->clock()),
            Provisioner::class => static fn(Graph $graph): Provisioner => new Provisioner($graph->users(), $graph->database(), $graph->unitOfWork(), $graph->events(), $graph->clock()),
            SsoAudit::class => static fn(Graph $graph): SsoAudit => new SsoAudit(self::recorder($graph), $graph->clock()),
            OidcProtocol::class => fn(Graph $graph): OidcProtocol => $this->oidc ?? ($this->httpClient !== null && $this->requestFactory !== null && $this->streamFactory !== null
                ? new HttpOidcProtocol($this->httpClient, $this->requestFactory, $this->streamFactory, $graph->cache())
                : new UnconfiguredOidc()),
            SamlProtocol::class => fn(): SamlProtocol => $this->saml ?? new OneLoginSamlProtocol(),
            DomainVerifier::class => fn(): DomainVerifier => $this->domains ?? new DnsHttpsDomainVerifier($this->httpClient, $this->requestFactory),
            SsoService::class => static fn(Graph $graph): SsoService => new SsoService(
                $graph->get(Providers::class),
                $graph->get(Domains::class),
                $graph->get(Provisioner::class),
                $graph->get(SsoAudit::class),
                $graph->get(Sp::class),
                $graph->get(OidcProtocol::class),
                $graph->get(SamlProtocol::class),
                $graph->cache(),
                $graph->tokens(),
                $graph->principals(),
                $graph->sessions(),
                $graph->users(),
                $graph->events(),
                $graph->clock(),
            ),
        ];
    }

    #[Override]
    public function listeners(Graph $graph): array
    {
        self::catalog($graph);

        return [];
    }

    /**
     * The `sso.*` names join the audit catalog: the audit plugin must be registered.
     */
    public static function catalog(Graph $graph): Catalog
    {
        AuditPlugin::of($graph);
        $catalog = $graph->get(Catalog::class);
        $catalog->extend(AuditNames::ALL);

        return $catalog;
    }

    private static function recorder(Graph $graph): Recorder
    {
        self::catalog($graph);

        return $graph->get(Recorder::class);
    }
}
