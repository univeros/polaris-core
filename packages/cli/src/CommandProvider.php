<?php

declare(strict_types=1);

namespace Polaris\Cli;

use Polaris\Wiring\Graph;
use Symfony\Component\Console\Command\Command;

/**
 * A plugin that ships console commands: `bin/polaris` adds them when a bootstrap
 * (`POLARIS_BOOTSTRAP`) names the application, and the adapters' consoles add them from the
 * application's plugins.
 */
interface CommandProvider
{
    /**
     * @return list<Command>
     */
    public function commands(Graph $graph): array;
}
