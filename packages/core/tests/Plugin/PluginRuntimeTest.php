<?php

declare(strict_types=1);

namespace Polaris\Tests\Plugin;

use HttpSoft\Message\ResponseFactory;
use HttpSoft\Message\ServerRequestFactory;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\Dialect;
use Polaris\Event\UserRegistered;
use Polaris\Http\Manifest\Loader;
use Polaris\Pdo\SqlSchema;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Schema\Field;
use Polaris\Schema\Model;
use Polaris\Schema\Schema;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\Plugin\SampleNote;
use Polaris\Tests\Support\Plugin\SampleNotes;
use Polaris\Tests\Support\Plugin\SamplePlugin;
use Polaris\Tests\Support\TestKeys;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;

use function array_filter;
use function file_put_contents;
use function implode;
use function json_decode;
use function mkdir;
use function str_contains;
use function str_repeat;
use function sys_get_temp_dir;
use function uniqid;

/**
 * The plugin runtime: a plugin's models, routes, services, listeners and permissions join core's
 * through `Polaris::create()`. Each test runs in its own process because `Schema` registers plugins
 * statically.
 */
#[CoversClass(Graph::class)]
#[CoversClass(Schema::class)]
#[CoversClass(Loader::class)]
#[CoversClass(AbstractPlugin::class)]
#[RunTestsInSeparateProcesses]
final class PluginRuntimeTest extends TestCase
{
    public function testAPluginsModelsJoinTheSchemaAndTheSqlExport(): void
    {
        self::assertCount(15, Schema::all());
        $polaris = self::polaris(new SamplePlugin());

        self::assertCount(16, $polaris->schema());
        self::assertSame('polaris_sample_note', Schema::for(SampleNote::class)->table);
        self::assertTrue(self::mentions('polaris_sample_note', SqlSchema::createAll(Dialect::Sqlite)));
        self::assertTrue(self::mentions('polaris_sample_note', SqlSchema::dropAll(Dialect::Postgres)));
        self::assertCount(16, Schema::all(), 'registering twice adds nothing');
        self::polaris(new SamplePlugin());
        self::assertCount(16, Schema::all());
    }

    public function testAPluginCannotRedefineACoreTable(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('core model');
        Schema::register(Model::table('auth_users', SampleNote::class, [Field::string('id', 36)->primary()]));
    }

    public function testAPluginsRoutesJoinTheManifestAndDuplicatesAreRejected(): void
    {
        $polaris = self::polaris(new SamplePlugin());

        self::assertCount(53, $polaris->manifest()->endpoints());
        self::assertSame('sample/notes.yaml', $polaris->manifest()->find('GET', '/sample/notes')?->file);

        $directory = sys_get_temp_dir() . '/polaris-plugin-' . uniqid();
        mkdir($directory . '/dup', 0777, true);
        file_put_contents($directory . '/dup/me.yaml', "endpoint: { method: GET, path: /auth/me, auth: public, effect: read }\ndomain: { class: Polaris\\Tests\\Support\\Plugin\\SampleNotesEndpoint }\noutput: { status: 200, example: { data: [] } }\n");
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('already declared');
        (new Loader(Loader::defaultDirectory(), $directory))->load();
    }

    public function testTheGraphBuildsPluginServicesForEndpointsAndProblemsRenderAsProblemJson(): void
    {
        $polaris = self::polaris(new SamplePlugin());
        $graph = $polaris->graph();
        $pipeline = new Pipeline($graph, new ResponseFactory());

        $response = $pipeline->handle((new ServerRequestFactory())->createServerRequest('GET', '/sample/notes'));
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertSame('seen', $response->getHeaderLine('X-Sample'), 'the plugin middleware ran in the pipeline');
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('hello', $body['data'][0]['text']);
        self::assertSame('repository: Polaris\\Repository\\UserRepository', $body['data'][1]['text'], 'the plugin service took a core service from the graph');
        self::assertSame($graph->get(SampleNotes::class), $graph->get(SampleNotes::class), 'built once');

        $problem = $pipeline->handle((new ServerRequestFactory())->createServerRequest('GET', '/sample/notes?fail=1')->withQueryParams(['fail' => '1']));
        self::assertSame(403, $problem->getStatusCode());
        self::assertSame('application/problem+json', $problem->getHeaderLine('Content-Type'));
        self::assertSame([
            'type' => 'https://polaris.univeros.io/problems/sample/forbidden',
            'title' => 'Forbidden',
            'status' => 403,
            'detail' => 'The sample says no.',
            'error' => 'sample_forbidden',
            'message' => 'The sample says no.',
            'hint' => 'drop ?fail=1',
        ], json_decode((string) $problem->getBody(), true));
    }

    public function testListenersPermissionsAndLookupByIdAndDuplicateIds(): void
    {
        $plugin = new SamplePlugin();
        $polaris = self::polaris($plugin);

        self::assertCount(4, $polaris->listeners(), 'core\'s three plus the plugin\'s');
        $event = new UserRegistered('018f', 'ada@example.com', 'verification-token');
        foreach ($polaris->listeners() as $listener) {
            $listener($event);
        }
        self::assertSame([$event], $plugin->seen);
        self::assertSame('Read the sample notes', $polaris->graph()->permissionCatalog()->permissions()['sample.read']);
        self::assertSame($plugin, $polaris->plugin('sample'));

        try {
            $polaris->plugin('nope');
            self::fail('unknown id');
        } catch (LogicException $exception) {
            self::assertStringContainsString('"nope"', $exception->getMessage());
        }
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('id "sample"');
        self::polaris(new SamplePlugin(), new SamplePlugin());
    }

    public function testAnEndpointAskingForAnUnknownServiceIsAClearError(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('no Polaris service or plugin provides');
        self::polaris()->graph()->get(SampleNotes::class);
    }

    private static function polaris(AbstractPlugin ...$plugins): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            plugins: $plugins,
        ));
    }

    /**
     * @param list<string> $statements
     */
    private static function mentions(string $table, array $statements): bool
    {
        return array_filter($statements, static fn(string $sql): bool => str_contains($sql, $table)) !== [];
    }
}
