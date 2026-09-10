<?php

declare(strict_types=1);

namespace Polaris\Laravel\Tests;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

use function bin2hex;
use function dirname;
use function escapeshellarg;
use function exec;
use function file_put_contents;
use function mkdir;
use function random_bytes;
use function sprintf;
use function sys_get_temp_dir;

/**
 * bin/check-imports keeps framework namespaces inside their adapter package (spec §0.4).
 */
#[CoversNothing]
final class CheckImportsTest extends TestCase
{
    public function testFrameworkNamespacesOutsideTheirAdapterFailTheCheck(): void
    {
        $root = sys_get_temp_dir() . '/polaris-imports-' . bin2hex(random_bytes(4));
        foreach (['packages/core/src', 'packages/laravel/src', 'packages/symfony/src'] as $directory) {
            mkdir($root . '/' . $directory, 0777, true);
        }
        // The namespaces are assembled at runtime: this file is scanned by the check too.
        file_put_contents($root . '/packages/laravel/src/Fine.php', self::imports('Illuminate', 'Support\\Str') . self::imports('Symfony', 'Component\\HttpFoundation\\Response'));
        file_put_contents($root . '/packages/symfony/src/Fine.php', self::imports('Symfony', 'Bundle\\FrameworkBundle\\FrameworkBundle'));
        self::assertSame(0, self::check($root));

        foreach ([['Illuminate', 'Support\\Str'], ['Altair', 'Http\\Request'], ['Yiisoft', 'Router\\Route'], ['Symfony', 'Component\\HttpKernel\\Kernel']] as [$vendor, $class]) {
            file_put_contents($root . '/packages/core/src/Leak.php', self::imports($vendor, $class));
            self::assertSame(1, self::check($root), $vendor);
        }
    }

    private static function imports(string $vendor, string $class): string
    {
        return sprintf("<?php\nuse %s\\%s;\n", $vendor, $class);
    }

    private static function check(string $root): int
    {
        exec(sprintf('%s %s 2>&1', escapeshellarg(dirname(__DIR__, 3) . '/bin/check-imports'), escapeshellarg($root)), $output, $code);

        return $code;
    }
}
