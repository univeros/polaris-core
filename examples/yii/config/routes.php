<?php

declare(strict_types=1);

use PolarisDemo\MeAction;
use Yiisoft\Router\Route;

// The application's own routes; /app/me needs a Polaris access token (the polaris/authentication middleware).
return [
    Route::get('/app/me')->middleware('polaris/authentication')->action(MeAction::class)->name('app/me'),
];
