<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Contract;

use PHPUnit\Framework\Assert;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function count;
use function file_get_contents;
use function is_file;
use function parse_url;
use function preg_replace;
use function json_decode;
use function sprintf;
use function str_replace;

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
     */
    private function __construct(private readonly string $test, array $steps)
    {
        $this->steps = $steps;
    }

    public static function directory(): string
    {
        return __DIR__ . '/fixtures';
    }

    public static function for(string $test): ?self
    {
        $file = self::directory() . '/' . str_replace(['\\', '::'], '.', $test) . '.json';
        if (!is_file($file)) {
            return null;
        }
        /** @var list<array{request: array<string, mixed>, response: array<string, mixed>}> $steps */
        $steps = json_decode((string) file_get_contents($file), true);

        return new self($test, $steps);
    }

    public function compare(ServerRequestInterface $request, ResponseInterface $response): void
    {
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
        ]);
        $expected = KnownChanges::all()[$this->test][$this->cursor + 1] ?? Normalizer::response($step['response']);
        Assert::assertSame($expected, $actual, $label);
        ++$this->cursor;
    }

    private static function path(string $path): string
    {
        return (string) preg_replace('/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i', '<uuid>', $path);
    }

    public function assertConsumed(): void
    {
        Assert::assertSame(count($this->steps), $this->cursor, sprintf('%s: 1.0 recorded %d requests, the replay issued %d', $this->test, count($this->steps), $this->cursor));
    }
}
