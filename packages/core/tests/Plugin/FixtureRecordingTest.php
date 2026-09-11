<?php

declare(strict_types=1);

namespace Polaris\Tests\Plugin;

use HttpSoft\Message\ResponseFactory;
use HttpSoft\Message\ServerRequestFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Tests\Contract\Fixture;

use function file_get_contents;
use function is_file;
use function json_decode;
use function putenv;
use function sys_get_temp_dir;
use function uniqid;

/**
 * A plugin's functional tests record their fixtures once (`POLARIS_RECORD_FIXTURES`) and replay them
 * afterwards, from their own directory.
 */
#[CoversClass(Fixture::class)]
final class FixtureRecordingTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('POLARIS_RECORD_FIXTURES');
    }

    public function testRecordsThenReplays(): void
    {
        $directory = sys_get_temp_dir() . '/polaris-fixtures-' . uniqid();
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/sample/notes')->withHeader('Content-Type', 'application/json')->withParsedBody(['text' => 'hi']);
        $response = (new ResponseFactory())->createResponse(201)->withHeader('Content-Type', 'application/json');
        $response->getBody()->write('{"data":{"id":"n1"}}');

        self::assertNull(Fixture::for('Some\\Test::testNothing', [], $directory), 'no file, no recording flag: nothing to compare');

        putenv('POLARIS_RECORD_FIXTURES=1');
        $recording = Fixture::for('Some\\Test::testIt', [], $directory);
        self::assertNotNull($recording);
        $recording->compare($request, $response);
        $recording->compare($request, $response);
        $recording->assertConsumed();
        $file = $directory . '/Some.Test.testIt.json';
        self::assertTrue(is_file($file));
        $steps = json_decode((string) file_get_contents($file), true);
        self::assertCount(2, $steps);
        self::assertSame(['text' => 'hi'], $steps[0]['request']['body']);
        self::assertSame(['data' => ['id' => 'n1']], $steps[1]['response']['body']);

        putenv('POLARIS_RECORD_FIXTURES');
        $replay = Fixture::for('Some\\Test::testIt', ['x-transport'], $directory);
        self::assertNotNull($replay);
        $replay->compare($request, $response);
        $replay->compare($request, $response);
        $replay->assertConsumed();
    }
}
