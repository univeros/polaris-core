<?php

declare(strict_types=1);

use Polaris\Cli\Command\DoctorCommand;
use Polaris\Cli\Command\ManifestCommand;
use Polaris\Cli\Command\SchemaCreateCommand;
use Polaris\Cli\Command\SchemaDiffCommand;
use Polaris\Cli\Command\SchemaDropCommand;
use Polaris\Cli\Command\SchemaExportCommand;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Yii\Factory;
use Psr\Container\ContainerInterface;
use Yiisoft\Definitions\DynamicReference;

// The polaris/cli commands on the application's connection, secrets and settings, under the names
// params.php registers with yiisoft/yii-console.
$connection = DynamicReference::to(static fn (ContainerInterface $container): Closure => static fn (): PDO => Factory::connection($container));
$secrets = DynamicReference::to(static fn (ContainerInterface $container): Closure => static fn (): Secrets => $container->get(Secrets::class));
$auth = DynamicReference::to(static fn (ContainerInterface $container): Closure => static fn (): AuthConfig => $container->get(AuthConfig::class));

return [
    SchemaExportCommand::class => ['class' => SchemaExportCommand::class, 'setName()' => ['polaris:schema:export']],
    SchemaCreateCommand::class => ['class' => SchemaCreateCommand::class, '__construct()' => ['connection' => $connection], 'setName()' => ['polaris:schema:create']],
    SchemaDropCommand::class => ['class' => SchemaDropCommand::class, '__construct()' => ['connection' => $connection], 'setName()' => ['polaris:schema:drop']],
    SchemaDiffCommand::class => ['class' => SchemaDiffCommand::class, '__construct()' => ['connection' => $connection], 'setName()' => ['polaris:schema:diff']],
    ManifestCommand::class => ['class' => ManifestCommand::class, 'setName()' => ['polaris:manifest']],
    DoctorCommand::class => ['class' => DoctorCommand::class, '__construct()' => ['secrets' => $secrets, 'auth' => $auth, 'connection' => $connection], 'setName()' => ['polaris:doctor']],
];
