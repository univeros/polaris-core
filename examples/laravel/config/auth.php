<?php

declare(strict_types=1);

// The `polaris` guard for the application's own routes: `Route::middleware('auth:polaris')`.
return [
    'guards' => [
        'polaris' => ['driver' => 'polaris'],
    ],
];
