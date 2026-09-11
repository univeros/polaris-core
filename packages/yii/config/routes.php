<?php

declare(strict_types=1);

use Polaris\Http\Manifest\Loader;
use Polaris\Yii\Factory;
use Polaris\Yii\Http\PolarisController;
use Yiisoft\Router\Route;

/** @var array $params */
$polaris = $params['polaris'];

// One named route per manifest endpoint, plugins' included (`polaris.auth.login`, ...) under path_prefix, all served by
// the controller, which runs the whole Polaris middleware stack and handler.
$prefix = rtrim((string) $polaris['path_prefix'], '/');
$manifest = (new Loader(...Factory::manifestDirectories($polaris)))->load();
$routes = [];
foreach ($manifest->endpoints() as $spec) {
    $routes[] = Route::methods([$spec->method], $prefix . $spec->path)
        ->name('polaris.' . str_replace('/', '.', substr($spec->file, 0, -5)))
        ->action([PolarisController::class, 'handle']);
}

return $routes;
