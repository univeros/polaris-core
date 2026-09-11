<?php

declare(strict_types=1);

namespace Polaris\Cli;

use Polaris\Polaris;
use Polaris\Wiring\Config;
use RuntimeException;

use function getenv;
use function is_file;
use function is_string;
use function sprintf;

/**
 * `--bootstrap=<file>` (or `POLARIS_BOOTSTRAP`): a PHP file returning the application's `Polaris`
 * instance or its `Config`, so the commands see the plugins the application registers (their
 * tables, permissions and routes). Without one they see core alone, as a fresh checkout does.
 */
final class Bootstrap
{
    public static function load(mixed $option): ?Polaris
    {
        $file = is_string($option) && $option !== '' ? $option : getenv('POLARIS_BOOTSTRAP');
        if (!is_string($file) || $file === '') {
            return null;
        }
        if (!is_file($file)) {
            throw new RuntimeException(sprintf('The bootstrap file %s does not exist.', $file));
        }
        $result = require $file;
        if ($result instanceof Config) {
            $result = Polaris::create($result);
        }
        if (!$result instanceof Polaris) {
            throw new RuntimeException(sprintf('%s must return a Polaris\Polaris instance or a Polaris\Wiring\Config.', $file));
        }

        return $result;
    }
}
