<?php

declare(strict_types=1);

use Altair\Configuration\Contracts\ConfigurationInterface;
use Altair\Container\Container;
use Altair\Module\Contracts\ModuleInterface;
use Altair\Module\ModuleConfiguration;

/*
 * Boot factory, as in the Univeros skeleton: build the container, apply the Configuration chain,
 * then the registered modules (config/modules.php).
 */
$container = new Container();

/** @var list<ConfigurationInterface> $configurations */
$configurations = require __DIR__ . '/configurations.php';
foreach ($configurations as $configuration) {
    $configuration->apply($container);
}

/** @var list<ModuleInterface> $modules */
$modules = require __DIR__ . '/modules.php';
(new ModuleConfiguration($modules))->apply($container);

return $container;
