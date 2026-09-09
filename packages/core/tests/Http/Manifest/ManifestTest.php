<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Http\Manifest;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Config\RateLimitConfig;
use Polaris\Http\Auth\OtpFactorConfirmEndpoint;
use Polaris\Http\Endpoint;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Http\Manifest\Loader;
use Polaris\Http\Manifest\Manifest;
use ReflectionClass;

use function array_count_values;
use function array_map;
use function array_unique;
use function class_exists;
use function count;
use function file_get_contents;
use function glob;
use function in_array;
use function is_subclass_of;
use function json_decode;
use function lcfirst;
use function preg_replace_callback;
use function property_exists;
use function sort;
use function str_ends_with;
use function strtoupper;

#[CoversClass(Loader::class)]
#[CoversClass(Manifest::class)]
#[CoversClass(EndpointSpec::class)]
final class ManifestTest extends TestCase
{
    /** Endpoint classes 1.0 already served from more than one route. */
    private const array SHARED = [OtpFactorConfirmEndpoint::class];

    private Manifest $manifest;

    protected function setUp(): void
    {
        $this->manifest = (new Loader(Loader::defaultDirectory()))->load();
    }

    public function testEverySpecRoutesToAnEndpointAndEveryEndpointIsSpecified(): void
    {
        self::assertCount(52, $this->manifest->endpoints());

        $referenced = [];
        foreach ($this->manifest->endpoints() as $spec) {
            self::assertTrue(class_exists($spec->class), "$spec->file: $spec->class");
            self::assertTrue(is_subclass_of($spec->class, Endpoint::class), "$spec->file: $spec->class must extend Endpoint");
            $referenced[] = $spec->class;
        }
        foreach (array_count_values($referenced) as $class => $count) {
            self::assertTrue($count === 1 || in_array($class, self::SHARED, true), "$class is referenced by $count specs");
        }

        $endpoints = [];
        foreach (glob(Loader::defaultDirectory() . '/../packages/core/src/Http/*/*Endpoint.php') ?: [] as $file) {
            $class = 'Polaris\\Http\\' . basename(dirname($file)) . '\\' . basename($file, '.php');
            if (class_exists($class) && !(new ReflectionClass($class))->isAbstract()) {
                $endpoints[] = $class;
            }
        }
        $unreferenced = array_diff($endpoints, array_unique($referenced));
        self::assertSame([], array_values($unreferenced), 'every Endpoint class is referenced by a spec');
    }

    public function testRoutesAreUniqueAndFindable(): void
    {
        $routes = array_map(static fn(EndpointSpec $s): string => $s->route(), $this->manifest->endpoints());
        self::assertSame(count($routes), count(array_unique($routes)));
        self::assertSame('Polaris\\Http\\Auth\\LoginEndpoint', $this->manifest->find('post', '/auth/login')?->class);
        self::assertNull($this->manifest->find('GET', '/nope'));
    }

    public function testPolicyValuesAreKnown(): void
    {
        $limits = RateLimitConfig::defaults();
        foreach ($this->manifest->endpoints() as $spec) {
            self::assertContains($spec->auth, EndpointSpec::AUTH, $spec->file);
            self::assertContains($spec->effect, EndpointSpec::EFFECTS, $spec->file);
            self::assertContains($spec->inputSource, EndpointSpec::SOURCES, $spec->file);
            self::assertSame($spec->method, strtoupper($spec->method), $spec->file);
            if ($spec->rateLimit !== null) {
                $property = lcfirst((string) preg_replace_callback('/_(\w)/', static fn(array $m): string => strtoupper($m[1]), $spec->rateLimit));
                self::assertTrue(property_exists($limits, $property), "$spec->file: rate_limit $spec->rateLimit is not a RateLimitConfig group");
            }
            self::assertSame($spec->effect !== 'read', $spec->receipt, "$spec->file: receipt follows the effect unless overridden");
            if ($spec->method === 'GET') {
                self::assertSame('read', $spec->effect, "$spec->file: GET is a read");
            }
        }
    }

    public function testSchemaJsonAgreesWithTheLoader(): void
    {
        $schema = json_decode((string) file_get_contents(Loader::defaultDirectory() . '/schema.json'), true);

        self::assertIsArray($schema);
        self::assertSame(['endpoint', 'domain'], $schema['required']);
        self::assertSame(['method', 'path', 'auth', 'effect'], $schema['properties']['endpoint']['required']);
        self::assertSame(EndpointSpec::AUTH, $schema['properties']['endpoint']['properties']['auth']['enum']);
        self::assertSame(EndpointSpec::EFFECTS, $schema['properties']['endpoint']['properties']['effect']['enum']);
        self::assertSame(EndpointSpec::SOURCES, $schema['properties']['input']['properties']['source']['enum']);
        self::assertSame(['class'], $schema['properties']['domain']['required']);
    }

    public function testSpecFilesAreTheOnlyYamlUnderApi(): void
    {
        $files = [];
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(Loader::defaultDirectory())) as $file) {
            if ($file instanceof \SplFileInfo && str_ends_with($file->getFilename(), '.yaml')) {
                $files[] = $file->getPathname();
            }
        }
        sort($files);
        self::assertCount(52, $files);
    }
}
