<?php

declare(strict_types=1);

use Illuminate\Foundation\Application;
use PolarisDemo\FileMailer;

// The whole host: a Laravel application with polaris/laravel discovered as a package, and the demo's
// mailbox (a JSON-lines file the walkthrough reads) bound for config/polaris.php's `mailer`.
return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(health: '/up')
    ->withSingletons([
        FileMailer::class => static fn (): FileMailer => new FileMailer(storage_path('mail.log')),
    ])
    ->create();
