<?php

declare(strict_types=1);

namespace Polaris\Wiring;

use LogicException;
use Polaris\Authorization\EscalationGuard;
use Polaris\Authorization\Gate;
use Polaris\Authorization\InvitationService;
use Polaris\Authorization\MembershipService;
use Polaris\Authorization\OrganizationService;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\PermissionResolver;
use Polaris\Authorization\RbacSessionPrincipalResolver;
use Polaris\Authorization\RoleService;
use Polaris\Config\AuthConfig;
use Polaris\Config\RateLimitConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\BreachedPasswordCheckInterface;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\EncrypterInterface;
use Polaris\Contract\IdentityProviderInterface;
use Polaris\Contract\MetricsInterface;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Schema\Schema;
use Polaris\Contract\Plugin;
use Polaris\Contract\PasswordHasherInterface;
use Polaris\Contract\QrCodeRendererInterface;
use Polaris\Contract\RateStore;
use Polaris\Contract\RepositoryInterface;
use Polaris\Contract\SmsSenderInterface;
use Polaris\Contract\TokenConfigurationInterface;
use Polaris\Contract\TokenFactoryInterface;
use Polaris\Contract\TokenGeneratorInterface;
use Polaris\Contract\TokenParserInterface;
use Polaris\Contract\TokenValidatorInterface;
use Polaris\Contract\TotpProviderInterface;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Event\NullEventDispatcher;
use Polaris\Exception\InvalidConfigException;
use Polaris\Http\Auth\MeEndpoint;
use Polaris\Http\Auth\SwitchOrgEndpoint;
use Polaris\Http\Endpoint;
use Polaris\Http\Manifest\Loader;
use Polaris\Http\Manifest\Manifest;
use Polaris\Http\Orgs\ReadOrganizationEndpoint;
use Polaris\Identity\RepositoryIdentityProvider;
use Polaris\Identity\EmailVerificationService;
use Polaris\Identity\LoginService;
use Polaris\Identity\MfaLoginService;
use Polaris\Identity\PasswordPolicy;
use Polaris\Identity\PasswordResetService;
use Polaris\Identity\RegistrationService;
use Polaris\Identity\SessionService;
use Polaris\Identity\StepUpService;
use Polaris\Identity\UserAdminService;
use Polaris\Maintenance\PruneExpiredService;
use Polaris\Mfa\EndroidQrRenderer;
use Polaris\Mfa\LogOtpMailer;
use Polaris\Mfa\LogSmsSender;
use Polaris\Mfa\MfaChallengeVerifier;
use Polaris\Mfa\MfaConfirmation;
use Polaris\Mfa\MfaEnforcement;
use Polaris\Mfa\MfaManagementService;
use Polaris\Mfa\MfaTotpService;
use Polaris\Mfa\OtpFactorService;
use Polaris\Mfa\OtphpTotpProvider;
use Polaris\Mfa\OtpService;
use Polaris\Mfa\RecoveryCodeService;
use Polaris\Notification\NotificationListener;
use Polaris\Observability\AuditLogListener;
use Polaris\Observability\MetricsListener;
use Polaris\Repository\EmailVerificationRepository;
use Polaris\Repository\IdentityMap;
use Polaris\Repository\InvitationRepository;
use Polaris\Repository\MembershipRepository;
use Polaris\Repository\MembershipRoleRepository;
use Polaris\Repository\MfaFactorRepository;
use Polaris\Repository\OrganizationRepository;
use Polaris\Repository\OtpChallengeRepository;
use Polaris\Repository\PasswordResetRepository;
use Polaris\Repository\PermissionRepository;
use Polaris\Repository\RecoveryCodeRepository;
use Polaris\Repository\RefreshTokenRepository;
use Polaris\Repository\RolePermissionRepository;
use Polaris\Repository\RoleRepository;
use Polaris\Repository\UnitOfWork;
use Polaris\Repository\UserRepository;
use Polaris\Security\Argon2idPasswordHasher;
use Polaris\Security\NullBreachedPasswordCheck;
use Polaris\Security\Pepper;
use Polaris\Security\SodiumEncrypter;
use Polaris\Support\CacheRateStore;
use Polaris\Support\InMemoryCache;
use Polaris\Support\LogMetrics;
use Polaris\Support\SystemClock;
use Polaris\Token\AccessTokenDenylist;
use Polaris\Token\JwtSignerFactory;
use Polaris\Token\LcobucciTokenParser;
use Polaris\Token\MfaLoginTokenService;
use Polaris\Token\PolarisTokenFactory;
use Polaris\Token\PolarisTokenGenerator;
use Polaris\Token\PolarisTokenParser;
use Polaris\Token\PolarisTokenValidator;
use Polaris\Token\SessionPrincipalResolverInterface;
use Polaris\Token\TokenConfiguration;
use Polaris\Token\TokenService;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;
use ReflectionClass;
use ReflectionNamedType;

use function array_key_exists;
use function array_values;
use function sprintf;

/**
 * The Polaris object graph, built explicitly from a {@see Config}: every service once, in the
 * order the 1.0 wiring used, with no container. Endpoints are constructed from their typed
 * constructor parameters against the services this graph provides.
 */
final class Graph
{
    /** @var array<string, object> */
    private array $instances = [];

    private readonly Manifest $manifest;

    /** @var array<string, Plugin> by id */
    private readonly array $plugins;

    /** @var array<class-string, callable(Graph): object> */
    private readonly array $pluginServices;

    public function __construct(private readonly Config $config)
    {
        $plugins = [];
        $services = [];
        foreach ($config->plugins as $plugin) {
            if (isset($plugins[$plugin->id()])) {
                throw new LogicException(sprintf('Two plugins declare the id "%s".', $plugin->id()));
            }
            $plugins[$plugin->id()] = $plugin;
            Schema::register(...$plugin->schema());
            foreach ($plugin->services() as $class => $factory) {
                $services[$class] = $factory;
            }
        }
        $this->plugins = $plugins;
        $this->pluginServices = $services;
        $this->manifest = (new Loader(...$config->manifestDirectories()))->load();
    }

    /**
     * @return array<string, Plugin> by id, in registration order
     */
    public function plugins(): array
    {
        return $this->plugins;
    }

    public function plugin(string $id): Plugin
    {
        return $this->plugins[$id] ?? throw new LogicException(sprintf('No plugin "%s" is registered.', $id));
    }

    /**
     * A plugin-provided service (or any service an endpoint may ask for), built once.
     *
     * @template T of object
     * @param class-string<T> $class
     * @return T
     */
    public function get(string $class): object
    {
        /** @var T $service */
        $service = $this->service($class, $class);

        return $service;
    }

    public function manifest(): Manifest
    {
        return $this->manifest;
    }

    public function config(): Config
    {
        return $this->config;
    }

    // --- ports and their defaults -------------------------------------------------------------

    /**
     * A port a plugin provides through `services()` keyed by the contract (`polaris/messaging` provides the
     * mailer and the SMS sender), used when the Config leaves the port unset; null when no plugin does.
     * Public so a package can take another package's optional contribution the same way (`polaris/messaging`
     * takes `polaris/sentinel`'s `Suppressor`).
     *
     * @template T of object
     * @param class-string<T> $contract
     * @return T|null
     */
    public function port(string $contract): ?object
    {
        if (!isset($this->pluginServices[$contract])) {
            return null;
        }
        /** @var T $service */
        $service = $this->once($contract, fn(): object => ($this->pluginServices[$contract])($this));

        return $service;
    }

    public function clock(): ClockInterface
    {
        return $this->config->clock ?? $this->once(SystemClock::class, static fn(): SystemClock => new SystemClock());
    }

    public function cache(): CacheInterface
    {
        return $this->config->cache ?? $this->once(InMemoryCache::class, static fn(): InMemoryCache => new InMemoryCache());
    }

    public function events(): EventDispatcherInterface
    {
        return $this->config->dispatcher ?? $this->once(NullEventDispatcher::class, static fn(): NullEventDispatcher => new NullEventDispatcher());
    }

    public function logger(): LoggerInterface
    {
        return $this->config->logger ?? $this->once(NullLogger::class, static fn(): NullLogger => new NullLogger());
    }

    public function rateLimits(): RateLimitConfig
    {
        return $this->config->rateLimits ?? RateLimitConfig::defaults();
    }

    public function rateStore(): RateStore
    {
        return $this->config->rateStore ?? $this->once(CacheRateStore::class, fn(): CacheRateStore => new CacheRateStore($this->cache(), $this->clock()));
    }

    public function mailer(): OtpMailerInterface
    {
        return $this->config->mailer ?? $this->port(OtpMailerInterface::class) ?? $this->once(LogOtpMailer::class, fn(): LogOtpMailer => new LogOtpMailer($this->logger()));
    }

    public function sms(): SmsSenderInterface
    {
        return $this->config->sms ?? $this->port(SmsSenderInterface::class) ?? $this->once(LogSmsSender::class, fn(): LogSmsSender => new LogSmsSender($this->logger()));
    }

    public function breachCheck(): BreachedPasswordCheckInterface
    {
        return $this->config->breachCheck ?? $this->port(BreachedPasswordCheckInterface::class) ?? $this->once(NullBreachedPasswordCheck::class, static fn(): NullBreachedPasswordCheck => new NullBreachedPasswordCheck());
    }

    public function encrypter(): EncrypterInterface
    {
        return $this->config->encrypter ?? $this->once(SodiumEncrypter::class, fn(): SodiumEncrypter => new SodiumEncrypter($this->config->secrets->appKey));
    }

    public function totp(): TotpProviderInterface
    {
        return $this->config->totp ?? $this->once(OtphpTotpProvider::class, fn(): OtphpTotpProvider => new OtphpTotpProvider($this->config->auth->otp->totp, $this->clock()));
    }

    public function qrCodes(): QrCodeRendererInterface
    {
        return $this->config->qrCodes ?? $this->once(EndroidQrRenderer::class, static fn(): EndroidQrRenderer => new EndroidQrRenderer());
    }

    // --- persistence ----------------------------------------------------------------------------

    public function database(): DatabaseAdapter
    {
        return $this->config->database;
    }

    public function identities(): IdentityMap
    {
        return $this->once(IdentityMap::class, static fn(): IdentityMap => new IdentityMap());
    }

    public function unitOfWork(): UnitOfWork
    {
        return $this->once(UnitOfWork::class, fn(): UnitOfWork => new UnitOfWork($this->database(), $this->identities()));
    }

    /**
     * @template T of object
     * @param class-string<T> $class
     * @return T
     */
    private function repository(string $class): object
    {
        return $this->once($class, fn(): object => new $class($this->database(), $this->identities()));
    }

    public function users(): UserRepository
    {
        return $this->repository(UserRepository::class);
    }

    // --- security -------------------------------------------------------------------------------

    public function pepper(): Pepper
    {
        return $this->once(Pepper::class, fn(): Pepper => new Pepper($this->config->secrets->appKey));
    }

    public function passwordHasher(): PasswordHasherInterface
    {
        return $this->once(Argon2idPasswordHasher::class, static fn(): Argon2idPasswordHasher => new Argon2idPasswordHasher());
    }

    public function passwordPolicy(): PasswordPolicy
    {
        return $this->once(PasswordPolicy::class, fn(): PasswordPolicy => new PasswordPolicy(
            $this->config->auth->passwordMinLength,
            $this->config->auth->breachCheck ? $this->breachCheck() : null,
        ));
    }

    // --- tokens ---------------------------------------------------------------------------------

    public function tokenConfiguration(): TokenConfigurationInterface
    {
        return $this->once(TokenConfiguration::class, function (): TokenConfiguration {
            $secrets = $this->config->secrets;
            $auth = $this->config->auth;
            if ($secrets->jwtPublicKey === '' || $auth->issuer === '') {
                throw new InvalidConfigException('A JWT public key and issuer are required to mint tokens.');
            }

            return new TokenConfiguration(
                $secrets->jwtPublicKey,
                $auth->accessToken->ttl,
                JwtSignerFactory::create($auth->accessToken->signer),
                $auth->issuer,
                null,
                $secrets->jwtPrivateKey,
                $auth->audience,
            );
        });
    }

    public function tokenGenerator(): TokenGeneratorInterface
    {
        return $this->once(PolarisTokenGenerator::class, fn(): PolarisTokenGenerator => new PolarisTokenGenerator($this->tokenConfiguration(), $this->clock(), $this->config->secrets->jwtKid));
    }

    public function tokenParser(): TokenParserInterface
    {
        return $this->once(PolarisTokenParser::class, fn(): PolarisTokenParser => new PolarisTokenParser($this->tokenConfiguration(), $this->clock()));
    }

    public function tokenValidator(): TokenValidatorInterface
    {
        return $this->once(PolarisTokenValidator::class, fn(): PolarisTokenValidator => new PolarisTokenValidator($this->tokenParser()));
    }

    public function identityProvider(): IdentityProviderInterface
    {
        return $this->once(RepositoryIdentityProvider::class, fn(): RepositoryIdentityProvider => new RepositoryIdentityProvider($this->users()));
    }

    public function tokenFactory(): TokenFactoryInterface
    {
        return $this->once(PolarisTokenFactory::class, fn(): PolarisTokenFactory => new PolarisTokenFactory($this->tokenParser(), $this->tokenGenerator(), $this->identityProvider(), $this->clock()));
    }

    public function denylist(): AccessTokenDenylist
    {
        return $this->once(AccessTokenDenylist::class, fn(): AccessTokenDenylist => new AccessTokenDenylist($this->cache(), $this->clock(), $this->config->auth->accessToken->ttl));
    }

    public function permissionCatalog(): PermissionCatalog
    {
        return $this->once(PermissionCatalog::class, fn(): PermissionCatalog => new PermissionCatalog(array_values($this->plugins)));
    }

    public function permissionResolver(): PermissionResolver
    {
        return $this->once(PermissionResolver::class, fn(): PermissionResolver => new PermissionResolver(
            $this->users(),
            $this->repository(OrganizationRepository::class),
            $this->repository(MembershipRepository::class),
            $this->repository(MembershipRoleRepository::class),
            $this->repository(RoleRepository::class),
            $this->repository(RolePermissionRepository::class),
            $this->repository(PermissionRepository::class),
        ));
    }

    public function principals(): SessionPrincipalResolverInterface
    {
        return $this->once(RbacSessionPrincipalResolver::class, fn(): RbacSessionPrincipalResolver => new RbacSessionPrincipalResolver($this->users(), $this->permissionResolver(), $this->config->auth));
    }

    public function tokens(): TokenService
    {
        return $this->once(TokenService::class, fn(): TokenService => new TokenService(
            $this->repository(RefreshTokenRepository::class),
            $this->unitOfWork(),
            $this->pepper(),
            $this->tokenGenerator(),
            $this->principals(),
            $this->config->auth,
            $this->clock(),
            $this->events(),
            $this->database(),
        ));
    }

    public function sessions(): SessionService
    {
        return $this->once(SessionService::class, fn(): SessionService => new SessionService($this->repository(RefreshTokenRepository::class), $this->tokens(), $this->clock(), $this->events(), $this->denylist()));
    }

    public function gate(): Gate
    {
        return $this->once(Gate::class, fn(): Gate => new Gate($this->permissionResolver()));
    }

    // --- identity -------------------------------------------------------------------------------

    public function emailVerification(): EmailVerificationService
    {
        return $this->once(EmailVerificationService::class, fn(): EmailVerificationService => new EmailVerificationService(
            $this->users(),
            $this->repository(EmailVerificationRepository::class),
            $this->unitOfWork(),
            $this->pepper(),
            $this->clock(),
            $this->events(),
        ));
    }

    public function registration(): RegistrationService
    {
        return $this->once(RegistrationService::class, fn(): RegistrationService => new RegistrationService(
            $this->users(),
            $this->emailVerification(),
            $this->unitOfWork(),
            $this->passwordHasher(),
            $this->passwordPolicy(),
            $this->clock(),
            $this->events(),
        ));
    }

    public function login(): LoginService
    {
        return $this->once(LoginService::class, fn(): LoginService => new LoginService(
            $this->users(),
            $this->passwordHasher(),
            $this->tokens(),
            $this->mfaLogin(),
            $this->unitOfWork(),
            $this->config->auth,
            $this->clock(),
            $this->events(),
        ));
    }

    public function passwordReset(): PasswordResetService
    {
        return $this->once(PasswordResetService::class, fn(): PasswordResetService => new PasswordResetService(
            $this->users(),
            $this->repository(PasswordResetRepository::class),
            $this->unitOfWork(),
            $this->passwordHasher(),
            $this->passwordPolicy(),
            $this->pepper(),
            $this->sessions(),
            $this->clock(),
            $this->events(),
        ));
    }

    public function userAdmin(): UserAdminService
    {
        return $this->once(UserAdminService::class, fn(): UserAdminService => new UserAdminService(
            $this->users(),
            $this->repository(MfaFactorRepository::class),
            $this->repository(OtpChallengeRepository::class),
            $this->repository(EmailVerificationRepository::class),
            $this->repository(PasswordResetRepository::class),
            $this->permissionResolver(),
            $this->sessions(),
            $this->unitOfWork(),
            $this->pepper(),
            $this->clock(),
            $this->events(),
        ));
    }

    // --- MFA ------------------------------------------------------------------------------------

    public function otp(): OtpService
    {
        return $this->once(OtpService::class, fn(): OtpService => new OtpService(
            $this->repository(OtpChallengeRepository::class),
            $this->sms(),
            $this->mailer(),
            $this->pepper(),
            $this->config->auth->otp,
            $this->unitOfWork(),
            $this->clock(),
            $this->events(),
            $this->cache(),
            $this->database(),
        ));
    }

    public function recoveryCodes(): RecoveryCodeService
    {
        return $this->once(RecoveryCodeService::class, fn(): RecoveryCodeService => new RecoveryCodeService(
            $this->repository(RecoveryCodeRepository::class),
            $this->unitOfWork(),
            $this->pepper(),
            $this->clock(),
            $this->events(),
            $this->database(),
        ));
    }

    public function mfaConfirmation(): MfaConfirmation
    {
        return $this->once(MfaConfirmation::class, fn(): MfaConfirmation => new MfaConfirmation($this->repository(MfaFactorRepository::class), $this->recoveryCodes(), $this->unitOfWork(), $this->clock(), $this->events()));
    }

    public function mfaTotp(): MfaTotpService
    {
        return $this->once(MfaTotpService::class, fn(): MfaTotpService => new MfaTotpService(
            $this->repository(MfaFactorRepository::class),
            $this->totp(),
            $this->encrypter(),
            $this->qrCodes(),
            $this->mfaConfirmation(),
            $this->unitOfWork(),
            $this->clock(),
        ));
    }

    public function otpFactors(): OtpFactorService
    {
        return $this->once(OtpFactorService::class, fn(): OtpFactorService => new OtpFactorService($this->repository(MfaFactorRepository::class), $this->otp(), $this->mfaConfirmation(), $this->unitOfWork(), $this->clock()));
    }

    public function mfaLoginTokens(): MfaLoginTokenService
    {
        return $this->once(MfaLoginTokenService::class, function (): MfaLoginTokenService {
            $secrets = $this->config->secrets;
            $auth = $this->config->auth;
            $ticketConfig = new TokenConfiguration(
                $secrets->jwtPublicKey,
                $auth->mfaLoginTokenTtl,
                JwtSignerFactory::create($auth->accessToken->signer),
                $auth->issuer,
                null,
                $secrets->jwtPrivateKey,
                $auth->audience,
            );

            return new MfaLoginTokenService(
                new PolarisTokenGenerator($ticketConfig, $this->clock(), $secrets->jwtKid),
                new LcobucciTokenParser($this->tokenConfiguration(), $this->clock()),
            );
        });
    }

    public function mfaVerifier(): MfaChallengeVerifier
    {
        return $this->once(MfaChallengeVerifier::class, fn(): MfaChallengeVerifier => new MfaChallengeVerifier($this->repository(MfaFactorRepository::class), $this->mfaTotp(), $this->otp(), $this->recoveryCodes()));
    }

    public function mfaLogin(): MfaLoginService
    {
        return $this->once(MfaLoginService::class, fn(): MfaLoginService => new MfaLoginService($this->mfaVerifier(), $this->mfaLoginTokens(), $this->tokens(), $this->principals(), $this->clock(), $this->events()));
    }

    public function stepUp(): StepUpService
    {
        return $this->once(StepUpService::class, fn(): StepUpService => new StepUpService($this->mfaVerifier(), $this->tokens(), $this->events()));
    }

    public function mfaEnforcement(): MfaEnforcement
    {
        return $this->once(MfaEnforcement::class, fn(): MfaEnforcement => new MfaEnforcement($this->users(), $this->config->auth));
    }

    public function mfaManagement(): MfaManagementService
    {
        return $this->once(MfaManagementService::class, fn(): MfaManagementService => new MfaManagementService($this->repository(MfaFactorRepository::class), $this->mfaEnforcement(), $this->unitOfWork(), $this->clock(), $this->events()));
    }

    // --- organizations --------------------------------------------------------------------------

    public function escalationGuard(): EscalationGuard
    {
        return $this->once(EscalationGuard::class, fn(): EscalationGuard => new EscalationGuard($this->repository(RolePermissionRepository::class), $this->repository(PermissionRepository::class)));
    }

    public function organizations(): OrganizationService
    {
        return $this->once(OrganizationService::class, fn(): OrganizationService => new OrganizationService(
            $this->repository(OrganizationRepository::class),
            $this->repository(MembershipRepository::class),
            $this->repository(PermissionRepository::class),
            $this->permissionCatalog(),
            $this->sessions(),
            $this->unitOfWork(),
            $this->clock(),
            $this->events(),
        ));
    }

    public function memberships(): MembershipService
    {
        return $this->once(MembershipService::class, fn(): MembershipService => new MembershipService(
            $this->repository(MembershipRepository::class),
            $this->repository(MembershipRoleRepository::class),
            $this->repository(RoleRepository::class),
            $this->users(),
            $this->permissionResolver(),
            $this->escalationGuard(),
            $this->unitOfWork(),
            $this->sessions(),
            $this->clock(),
            $this->events(),
        ));
    }

    public function invitations(): InvitationService
    {
        return $this->once(InvitationService::class, fn(): InvitationService => new InvitationService(
            $this->repository(InvitationRepository::class),
            $this->repository(OrganizationRepository::class),
            $this->repository(MembershipRepository::class),
            $this->repository(MembershipRoleRepository::class),
            $this->repository(RoleRepository::class),
            $this->users(),
            $this->permissionResolver(),
            $this->escalationGuard(),
            $this->unitOfWork(),
            $this->pepper(),
            $this->clock(),
            $this->events(),
        ));
    }

    public function roles(): RoleService
    {
        return $this->once(RoleService::class, fn(): RoleService => new RoleService(
            $this->repository(RoleRepository::class),
            $this->repository(RolePermissionRepository::class),
            $this->repository(PermissionRepository::class),
            $this->permissionResolver(),
            $this->escalationGuard(),
            $this->unitOfWork(),
            $this->clock(),
            $this->events(),
        ));
    }

    public function metrics(): MetricsInterface
    {
        return $this->config->metrics ?? $this->port(MetricsInterface::class) ?? $this->once(LogMetrics::class, fn(): LogMetrics => new LogMetrics($this->logger()));
    }

    /**
     * The PSR-14 listeners Polaris ships (audit log, notifications, metrics). Subscribe them to the
     * dispatcher you pass in {@see Config}; each is a callable taking one event.
     *
     * @return list<callable(object): void>
     */
    public function listeners(): array
    {
        $listeners = [
            $this->once(AuditLogListener::class, fn(): AuditLogListener => new AuditLogListener($this->unitOfWork(), $this->clock(), $this->logger())),
            $this->once(NotificationListener::class, fn(): NotificationListener => new NotificationListener($this->mailer(), $this->users(), $this->logger())),
            $this->once(MetricsListener::class, fn(): MetricsListener => new MetricsListener($this->metrics(), $this->logger())),
        ];
        foreach ($this->plugins as $plugin) {
            foreach ($plugin->listeners($this) as $listener) {
                $listeners[] = $listener;
            }
        }

        return $listeners;
    }

    public function prune(): PruneExpiredService
    {
        return $this->once(PruneExpiredService::class, fn(): PruneExpiredService => new PruneExpiredService($this->database(), $this->clock()));
    }

    // --- endpoints ------------------------------------------------------------------------------

    /**
     * @param class-string $class
     */
    public function endpoint(string $class): Endpoint
    {
        $endpoint = $this->once($class, fn(): object => match ($class) {
            MeEndpoint::class => new MeEndpoint($this->users()),
            ReadOrganizationEndpoint::class => new ReadOrganizationEndpoint($this->repository(OrganizationRepository::class)),
            SwitchOrgEndpoint::class => new SwitchOrgEndpoint($this->tokens(), $this->repository(OrganizationRepository::class), $this->repository(MembershipRepository::class), $this->config->auth),
            default => $this->construct($class),
        });
        if (!$endpoint instanceof Endpoint) {
            throw new LogicException(sprintf('%s is not an endpoint.', $class));
        }

        return $endpoint;
    }

    /**
     * Builds an endpoint from its typed constructor parameters, each served by this graph.
     *
     * @param class-string $class
     */
    private function construct(string $class): object
    {
        $constructor = (new ReflectionClass($class))->getConstructor();
        $arguments = [];
        foreach ($constructor?->getParameters() ?? [] as $parameter) {
            $type = $parameter->getType();
            if (!$type instanceof ReflectionNamedType || $type->isBuiltin()) {
                throw new LogicException(sprintf('%s::$%s must be typed with a Polaris service.', $class, $parameter->getName()));
            }
            $arguments[] = $this->service($type->getName(), sprintf('%s::$%s', $class, $parameter->getName()));
        }

        return new $class(...$arguments);
    }

    /**
     * The service behind a constructor parameter type.
     */
    private function service(string $type, string $for): object
    {
        return match ($type) {
            AuthConfig::class => $this->config->auth,
            Secrets::class => $this->config->secrets,
            RateLimitConfig::class => $this->rateLimits(),
            UserRepository::class => $this->users(),
            OrganizationRepository::class, MembershipRepository::class, MembershipRoleRepository::class, RoleRepository::class,
            RolePermissionRepository::class, PermissionRepository::class, RefreshTokenRepository::class, MfaFactorRepository::class,
            OtpChallengeRepository::class, RecoveryCodeRepository::class, EmailVerificationRepository::class, PasswordResetRepository::class,
            InvitationRepository::class => $this->repository($type),
            RepositoryInterface::class => throw new LogicException(sprintf('%s needs an explicit repository; add it to Graph::endpoint().', $for)),
            UnitOfWorkInterface::class => $this->unitOfWork(),
            ClockInterface::class => $this->clock(),
            EventDispatcherInterface::class => $this->events(),
            TokenService::class => $this->tokens(),
            SessionService::class => $this->sessions(),
            Gate::class => $this->gate(),
            LoginService::class => $this->login(),
            RegistrationService::class => $this->registration(),
            EmailVerificationService::class => $this->emailVerification(),
            PasswordResetService::class => $this->passwordReset(),
            UserAdminService::class => $this->userAdmin(),
            MfaLoginService::class => $this->mfaLogin(),
            StepUpService::class => $this->stepUp(),
            MfaTotpService::class => $this->mfaTotp(),
            OtpFactorService::class => $this->otpFactors(),
            RecoveryCodeService::class => $this->recoveryCodes(),
            MfaManagementService::class => $this->mfaManagement(),
            OrganizationService::class => $this->organizations(),
            MembershipService::class => $this->memberships(),
            InvitationService::class => $this->invitations(),
            RoleService::class => $this->roles(),
            default => isset($this->pluginServices[$type])
                ? $this->once($type, fn(): object => ($this->pluginServices[$type])($this))
                : throw new LogicException(sprintf('%s: no Polaris service or plugin provides %s.', $for, $type)),
        };
    }

    /**
     * @template T of object
     * @param callable(): T $factory
     * @return T
     */
    private function once(string $key, callable $factory): object
    {
        if (!array_key_exists($key, $this->instances)) {
            $this->instances[$key] = $factory();
        }

        /** @var T $instance */
        $instance = $this->instances[$key];

        return $instance;
    }
}
