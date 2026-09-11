<?php

declare(strict_types=1);

namespace Polaris\Symfony;

use Nyholm\Psr7\Factory\Psr17Factory;
use Override;
use PDO;
use Polaris\Cli\Command\DoctorCommand;
use Polaris\Cli\Command\ManifestCommand;
use Polaris\Cli\Command\SchemaCreateCommand;
use Polaris\Cli\Command\SchemaDiffCommand;
use Polaris\Cli\Command\SchemaDropCommand;
use Polaris\Cli\Command\SchemaExportCommand;
use Polaris\Config\AuthConfig;
use Polaris\Config\RateLimitConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Pdo\PdoAdapter;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Symfony\Event\PolarisEventSubscriber;
use Polaris\Symfony\Http\PolarisController;
use Polaris\Symfony\Mail\OtpMailer;
use Polaris\Symfony\Routing\PolarisRouteLoader;
use Polaris\Symfony\Security\PolarisAuthenticator;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\SimpleCache\CacheInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ReferenceConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service_closure;
use function is_array;
use function array_map;
use function is_string;

/**
 * Polaris in a Symfony application: `polaris:` configuration (docs/adapters/spec.md §3.1) becomes the
 * `Polaris`, `Graph` and `Pipeline` services on the application's connection, cache, logger, event
 * dispatcher and mailer; the `polaris` route loader mounts the endpoints; the authenticator guards the
 * application's own firewalls; the `polaris:*` console commands.
 */
final class PolarisBundle extends AbstractBundle
{
    private const array SECRET_KEYS = ['app_key', 'jwt_private_key', 'jwt_public_key', 'jwt_kid', 'jwt_previous_public_key', 'jwt_previous_kid'];
    private const array PORTS = ['breach_check', 'clock', 'encrypter', 'metrics', 'totp', 'qr_codes', 'rate_store'];

    #[Override]
    public function configure(DefinitionConfigurator $definition): void
    {
        $root = $definition->rootNode();
        $children = $root->children();
        $children->scalarNode('path_prefix')->defaultValue('/')->info('Where the endpoints are mounted (also the prefix of the routes the "polaris" loader yields)');
        $children->scalarNode('manifest_directory')->defaultNull()->info('The api/**/*.yaml directory; null for the one shipped with polaris/core');
        $children->arrayNode('plugins')->scalarPrototype()->end()->info('Service ids of Polaris\\Contract\\Plugin instances; their tables, routes, services, listeners and permissions join core\'s');
        $secrets = $children->arrayNode('secrets')->addDefaultsIfNotSet()->children();
        $secrets->scalarNode('service')->defaultNull()->info('A Polaris\Config\Secrets service; the other keys are ignored then');
        foreach (self::SECRET_KEYS as $key) {
            $secrets->scalarNode($key)->defaultNull();
            if ($key !== 'app_key' && $key !== 'jwt_kid' && $key !== 'jwt_previous_kid') {
                $secrets->scalarNode($key . '_file')->defaultNull()->info('A PEM file, relative to the project directory');
            }
        }
        $children->variableNode('auth')->defaultValue([])->info('The docs/auth/configuration.md keys, or {service: id} for a Polaris\Config\AuthConfig service');
        $children->variableNode('rate_limits')->defaultValue([])->info('Per-group overrides, or {service: id}');
        $database = $children->arrayNode('database')->addDefaultsIfNotSet()->children();
        $database->scalarNode('service')->defaultNull()->info('A PDO, a Doctrine DBAL connection, a Polaris\Pdo\PdoAdapter or any DatabaseAdapter service');
        $database->scalarNode('dsn')->defaultNull();
        $database->scalarNode('user')->defaultNull();
        $database->scalarNode('password')->defaultNull();
        $children->scalarNode('cache')->defaultValue('cache.app')->info('A PSR-6 pool or PSR-16 cache service');
        $children->scalarNode('logger')->defaultValue('logger');
        $children->scalarNode('dispatcher')->defaultValue('event_dispatcher')->info('A PSR-14 dispatcher service; the Polaris listeners are subscribed to it');
        $children->scalarNode('mailer')->defaultValue('log')->info('log (codes go to the log), mail (Symfony Mailer), or an OtpMailerInterface service');
        $children->scalarNode('mail_from')->defaultNull()->info('The sender address for mailer: mail');
        $children->scalarNode('sms')->defaultValue('log')->info('log, or an SmsSenderInterface service');
        foreach (self::PORTS as $port) {
            $children->scalarNode($port)->defaultNull()->info('A service implementing the port; null for the core default');
        }
    }

    /**
     * @param array<string, mixed> $config
     */
    #[Override]
    public function loadExtension(array $config, ContainerConfigurator $configurator, ContainerBuilder $container): void
    {
        $services = $configurator->services();
        $prefix = (string) $config['path_prefix'];

        if (is_string($config['secrets']['service'] ?? null)) {
            $services->alias('polaris.secrets', $config['secrets']['service']);
        } else {
            $services->set('polaris.secrets', Secrets::class)->factory([Factory::class, 'secrets'])->args([$config['secrets'], param('kernel.project_dir')]);
        }
        $this->configOrService($configurator, 'polaris.auth', AuthConfig::class, $config['auth']);
        $this->configOrService($configurator, 'polaris.rate_limits', RateLimitConfig::class, $config['rate_limits']);

        $database = $config['database'];
        if (is_string($database['service'] ?? null)) {
            $services->set('polaris.pdo', PDO::class)->factory([Factory::class, 'pdo'])->args([service($database['service'])]);
            $services->set('polaris.database', DatabaseAdapter::class)->factory([Factory::class, 'adapter'])->args([service($database['service'])]);
        } elseif (is_string($database['dsn'] ?? null)) {
            $services->set('polaris.pdo', PDO::class)->factory([Factory::class, 'connect'])->args([$database['dsn'], $database['user'], $database['password']]);
            $services->set('polaris.database', PdoAdapter::class)->args([service('polaris.pdo')]);
        } else {
            throw new InvalidConfigurationException('polaris.database needs a "dsn" or a "service".');
        }
        $services->set('polaris.cache', CacheInterface::class)->factory([Factory::class, 'cache'])->args([service((string) $config['cache'])]);
        $services->alias('polaris.logger', (string) $config['logger']);
        $services->alias('polaris.dispatcher', (string) $config['dispatcher']);
        if ($config['mailer'] === 'mail') {
            $services->set('polaris.mail', OtpMailer::class)->args([service('mailer.mailer'), $config['mail_from']]);
        }

        $plugins = array_map(static fn(string $id): ReferenceConfigurator => service($id), $config['plugins']);
        $ports = [];
        foreach (self::PORTS as $port) {
            $ports[$port] = is_string($config[$port]) ? service($config[$port]) : null;
        }
        $services->set(Config::class)->args([
            '$secrets' => service('polaris.secrets'),
            '$auth' => service('polaris.auth'),
            '$database' => service('polaris.database'),
            '$mailer' => self::optional($config['mailer'] === 'mail' ? 'polaris.mail' : $config['mailer']),
            '$sms' => self::optional($config['sms']),
            '$breachCheck' => $ports['breach_check'],
            '$cache' => service('polaris.cache'),
            '$clock' => $ports['clock'],
            '$dispatcher' => service('polaris.dispatcher'),
            '$logger' => service('polaris.logger'),
            '$rateLimits' => service('polaris.rate_limits'),
            '$rateStore' => $ports['rate_store'],
            '$encrypter' => $ports['encrypter'],
            '$metrics' => $ports['metrics'],
            '$totp' => $ports['totp'],
            '$qrCodes' => $ports['qr_codes'],
            '$manifestDirectory' => $config['manifest_directory'],
            '$pathPrefix' => $prefix,
            '$plugins' => $plugins,
        ]);
        $services->set(Polaris::class)->factory([Polaris::class, 'create'])->args([service(Config::class)])->public();
        $services->set(Graph::class)->factory([service(Polaris::class), 'graph'])->public();
        $services->set(Psr17Factory::class);
        $services->set(PsrHttpFactory::class);
        $services->set(HttpFoundationFactory::class);
        $services->set(Pipeline::class)->args([service(Graph::class), service(Psr17Factory::class), $prefix])->public();
        $services->set(PolarisController::class)
            ->args([service(Pipeline::class), service(PsrHttpFactory::class), service(HttpFoundationFactory::class)])
            ->tag('controller.service_arguments')
            ->public();
        $services->set(PolarisRouteLoader::class)->args([$config['manifest_directory'], $prefix, $plugins])->tag('routing.loader');
        $services->set(PolarisEventSubscriber::class)->args([service(Polaris::class)])->tag('kernel.event_subscriber');
        $services->set(PolarisAuthenticator::class)->args([service(Graph::class)]);

        $services->set(SchemaExportCommand::class)->call('setName', ['polaris:schema:export'])->tag('console.command');
        $services->set(SchemaDiffCommand::class)->args([service_closure('polaris.pdo')])->call('setName', ['polaris:schema:diff'])->tag('console.command');
        $services->set(ManifestCommand::class)->call('setName', ['polaris:manifest'])->tag('console.command');
        $services->set(DoctorCommand::class)
            ->args([service_closure('polaris.secrets'), service_closure('polaris.auth'), service_closure('polaris.pdo')])
            ->call('setName', ['polaris:doctor'])
            ->tag('console.command');
        $services->set(SchemaCreateCommand::class)->args([service_closure('polaris.pdo')])->call('setName', ['polaris:schema:create'])->tag('console.command');
        $services->set(SchemaDropCommand::class)->args([service_closure('polaris.pdo')])->call('setName', ['polaris:schema:drop'])->tag('console.command');
    }

    /**
     * `{service: id}` aliases the host's service; anything else is the array the value object's
     * `fromArray()` takes.
     *
     * @param class-string $class
     */
    private function configOrService(ContainerConfigurator $configurator, string $id, string $class, mixed $value): void
    {
        if (is_array($value) && is_string($value['service'] ?? null)) {
            $configurator->services()->alias($id, $value['service']);

            return;
        }
        $configurator->services()->set($id, $class)->factory([$class, 'fromArray'])->args([is_array($value) ? $value : []]);
    }

    private static function optional(mixed $service): ?ReferenceConfigurator
    {
        return is_string($service) && $service !== '' && $service !== 'log' ? service($service) : null;
    }
}
