<?php

declare(strict_types=1);

use PolarisDemo\Env;
use Yiisoft\Yii\Runner\Http\HttpApplicationRunner;

require dirname(__DIR__) . '/vendor/autoload.php';

Env::load(dirname(__DIR__));

(new HttpApplicationRunner(rootPath: dirname(__DIR__), debug: true))->run();
