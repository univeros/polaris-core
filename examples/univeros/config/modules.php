<?php

declare(strict_types=1);

use PolarisDemo\PolarisModule;

/*
 * Modules installed in this app. PolarisModule builds Polaris from the environment and binds it,
 * its graph, the PSR-15 pipeline and the middleware that serves the Polaris routes.
 *
 * @return list<Altair\Module\Contracts\ModuleInterface>
 */
return [
    new PolarisModule(dirname(__DIR__)),
];
