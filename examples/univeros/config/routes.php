<?php

declare(strict_types=1);

use App\Http\Actions\PingAction;

/*
 * The application's own route table: [METHOD, PATH, Action::class]. The Polaris routes are not
 * listed here: PolarisMiddleware serves them before the dispatcher runs.
 */
return [
    ['GET', '/ping', PingAction::class],
];
