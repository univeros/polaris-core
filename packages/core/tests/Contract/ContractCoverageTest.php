<?php

declare(strict_types=1);

namespace Polaris\Tests\Contract;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Polaris\Http\Manifest\Loader;
use Polaris\Psr15\Router;

use function count;
use function file_get_contents;
use function glob;
use function json_decode;
use function parse_url;
use function sort;

use const PHP_URL_PATH;

/**
 * The recorded 1.0 fixtures reach every endpoint in the manifest, so the replay inside the
 * functional suite is a contract freeze for all 52 routes.
 */
#[CoversNothing]
final class ContractCoverageTest extends TestCase
{
    public function testEveryManifestRouteIsCoveredByARecordedFixture(): void
    {
        $manifest = (new Loader(Loader::defaultDirectory()))->load();
        $router = new Router($manifest);
        $covered = [];
        $steps = 0;
        foreach (glob(Fixture::directory() . '/*.json') ?: [] as $file) {
            foreach ((array) json_decode((string) file_get_contents($file), true) as $step) {
                ++$steps;
                $match = $router->match((string) $step['request']['method'], (string) parse_url((string) $step['request']['uri'], PHP_URL_PATH));
                if ($match->spec !== null) {
                    $covered[$match->spec->route()] = true;
                }
            }
        }

        $missing = [];
        foreach ($manifest->endpoints() as $spec) {
            if (!isset($covered[$spec->route()])) {
                $missing[] = $spec->route();
            }
        }
        sort($missing);
        self::assertSame([], $missing, 'every manifest route needs a recorded 1.0 fixture');
        self::assertGreaterThan(1000, $steps);
        self::assertSame(count($manifest->endpoints()), count($covered));
    }
}
