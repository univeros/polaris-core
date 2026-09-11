<?php

declare(strict_types=1);

namespace Polaris\Tests\Contract;

use PHPUnit\Framework\Assert;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function count;
use function dirname;
use function file_get_contents;
use function file_put_contents;
use function getenv;
use function is_dir;
use function is_file;
use function json_decode;
use function json_encode;
use function mkdir;
use function parse_url;
use function preg_replace;
use function sprintf;
use function str_replace;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const PHP_URL_PATH;

/**
 * The request/response steps one functional test produced against the 1.0 code through the
 * Univeros harness (recorded from the WP4 tree). Each replayed response is compared, normalised,
 * to the recorded one at the same step.
 */
final class Fixture
{
    /** @var list<array{request: array<string, mixed>, response: array<string, mixed>}> */
    private array $steps;
    private int $cursor = 0;

    /**
     * @param list<array{request: array<string, mixed>, response: array<string, mixed>}> $steps
     * @param list<string> $transportHeaders header names the host adds to every response, ignored
     */
    private function __construct(private readonly string $test, array $steps, private readonly array $transportHeaders)
    {
        $this->steps = $steps;
    }

    /** The file being recorded, when `POLARIS_RECORD_FIXTURES` is set and no fixture exists yet. */
    private ?string $recording = null;

    public static function directory(): string
    {
        return __DIR__ . '/fixtures';
    }

    /**
     * The fixture of a test: replayed when its file exists; recorded (raw request and response steps
     * written by {@see assertConsumed()}) when `POLARIS_RECORD_FIXTURES` is set and it does not, which
     * is how a plugin's functional tests get their fixtures from the PSR-15 harness; otherwise none.
     *
     * @param list<string> $transportHeaders
     * @param string|null $directory the fixtures directory, core's by default; a plugin passes its own
     */
    public static function for(string $test, array $transportHeaders = [], ?string $directory = null): ?self
    {
        $file = ($directory ?? self::directory()) . '/' . str_replace(['\\', '::'], '.', $test) . '.json';
        if (!is_file($file)) {
            if (getenv('POLARIS_RECORD_FIXTURES') === false) {
                return null;
            }
            $fixture = new self($test, [], $transportHeaders);
            $fixture->recording = $file;

            return $fixture;
        }
        /** @var list<array{request: array<string, mixed>, response: array<string, mixed>}> $steps */
        $steps = json_decode((string) file_get_contents($file), true);

        return new self($test, $steps, $transportHeaders);
    }

    public function compare(ServerRequestInterface $request, ResponseInterface $response): void
    {
        if ($this->recording !== null) {
            $this->record($request, $response);

            return;
        }
        $step = $this->steps[$this->cursor] ?? null;
        Assert::assertNotNull($step, sprintf('%s: step %d was not recorded from 1.0 (the test issues more requests than before)', $this->test, $this->cursor + 1));
        $recorded = $step['request'];
        $label = sprintf('%s: step %d %s %s', $this->test, $this->cursor + 1, $request->getMethod(), $request->getUri()->getPath());
        Assert::assertSame($recorded['method'], $request->getMethod(), $label . ' (method)');
        Assert::assertSame(self::path((string) parse_url((string) $recorded['uri'], PHP_URL_PATH)), self::path($request->getUri()->getPath()), $label . ' (path)');

        $body = (string) $response->getBody();
        $response->getBody()->rewind();
        if (($step['response']['status'] ?? null) === 404 && ($step['response']['body'] ?? '') === '') {
            // The 1.0 test harness answered unknown routes with a bare 404; the PSR-15 handler uses
            // the error envelope (spec §5.5). Only the status is contractual here.
            Assert::assertSame(404, $response->getStatusCode(), $label);
            ++$this->cursor;

            return;
        }
        $actual = Normalizer::response([
            'status' => $response->getStatusCode(),
            'headers' => $response->getHeaders(),
            'body' => json_decode($body, true) ?? $body,
        ], $this->transportHeaders);
        $expected = KnownChanges::all()[$this->test][$this->cursor + 1] ?? Normalizer::response($step['response'], $this->transportHeaders);
        Assert::assertSame($expected, $actual, $label);
        ++$this->cursor;
    }

    private static function path(string $path): string
    {
        return (string) preg_replace('/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i', '<uuid>', $path);
    }

    public function assertConsumed(): void
    {
        if ($this->recording !== null) {
            if (!is_dir(dirname($this->recording))) {
                mkdir(dirname($this->recording), 0777, true);
            }
            file_put_contents($this->recording, json_encode($this->steps, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");

            return;
        }
        Assert::assertSame(count($this->steps), $this->cursor, sprintf('%s: 1.0 recorded %d requests, the replay issued %d', $this->test, count($this->steps), $this->cursor));
    }

    /**
     * One raw step, in the shape the 1.0 recordings have: the request's method, URI, headers and
     * parsed body; the response's status, headers and decoded body.
     */
    private function record(ServerRequestInterface $request, ResponseInterface $response): void
    {
        $body = (string) $response->getBody();
        $response->getBody()->rewind();
        $parsed = $request->getParsedBody();
        $this->steps[] = [
            'request' => [
                'method' => $request->getMethod(),
                'uri' => (string) $request->getUri(),
                'headers' => $request->getHeaders(),
                'body' => $parsed === null || $parsed === [] ? (string) $request->getBody() : $parsed,
            ],
            'response' => [
                'status' => $response->getStatusCode(),
                'headers' => $response->getHeaders(),
                'body' => json_decode($body, true) ?? $body,
            ],
        ];
    }
}
