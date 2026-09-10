<?php

declare(strict_types=1);

namespace PolarisDemo;

use Altair\Container\Container;
use Altair\Module\Contracts\ModuleInterface;
use Laminas\Diactoros\ResponseFactory;
use Override;
use PDO;
use Polaris\Config\EnvironmentConfig;
use Polaris\Pdo\PdoAdapter;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Psr15\Router;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;

use function str_starts_with;

/**
 * The whole integration, as a Univeros module (config/modules.php): Polaris is built from the
 * environment on a PDO connection with the demo's mailbox and a PSR-14 dispatcher fed by
 * `Polaris::listeners()`, and the container gets Polaris, its graph, the PSR-15 pipeline and
 * {@see PolarisMiddleware}, which serves every Polaris route ahead of the dispatcher.
 */
final class PolarisModule implements ModuleInterface
{
    public function __construct(private readonly string $root)
    {
    }

    #[Override]
    public function name(): string
    {
        return 'polaris/example-univeros';
    }

    #[Override]
    public function apply(Container $container): void
    {
        Env::load($this->root);

        $dsn = Env::require('POLARIS_DSN');
        $pdo = new PDO(str_starts_with($dsn, 'sqlite:') ? 'sqlite:' . Env::sqlitePath($this->root, $dsn) : $dsn);
        $pdo->exec('PRAGMA foreign_keys = ON');

        $dispatcher = new Dispatcher();
        $polaris = Polaris::create(new Config(
            secrets: EnvironmentConfig::secrets(),
            auth: EnvironmentConfig::auth(),
            database: new PdoAdapter($pdo),
            mailer: new FileMailer($this->root . '/var/mail.log'),
            dispatcher: $dispatcher,
        ));
        foreach ($polaris->listeners() as $listener) {
            $dispatcher->listen($listener);
        }
        $pipeline = new Pipeline($polaris->graph(), new ResponseFactory());

        $container->instance(Polaris::class, $polaris);
        $container->instance(Graph::class, $polaris->graph());
        $container->instance(Pipeline::class, $pipeline);
        $container->instance(PolarisMiddleware::class, new PolarisMiddleware(new Router($polaris->manifest()), $pipeline));
    }
}
