<?php

declare(strict_types=1);

namespace Polaris\Tests\Support\Plugin;

use Override;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Schema\Field;
use Polaris\Schema\Model;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Everything a plugin can contribute, once each: a model, a route, a service, a listener, a permission.
 */
final class SamplePlugin extends AbstractPlugin
{
    /** @var list<object> */
    public array $seen = [];

    #[Override]
    public function id(): string
    {
        return 'sample';
    }

    #[Override]
    public function schema(): array
    {
        return [
            Model::table('polaris_sample_note', SampleNote::class, [
                Field::string('id', 36)->primary(),
                Field::string('text', 255),
                Field::datetime('createdAt'),
            ])->index(['created_at'], 'polaris_sample_note_created_index'),
        ];
    }

    #[Override]
    public static function manifestDirectory(): string
    {
        return __DIR__ . '/api';
    }

    #[Override]
    public function services(): array
    {
        return [SampleNotes::class => static fn(Graph $graph): SampleNotes => new SampleNotes($graph->users())];
    }

    #[Override]
    public function listeners(Graph $graph): array
    {
        return [function (object $event): void {
            $this->seen[] = $event;
        }];
    }

    #[Override]
    public function middleware(Graph $graph): array
    {
        return [new class implements MiddlewareInterface {
            public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
            {
                $response = $handler->handle($request);

                return $request->getUri()->getPath() === '/sample/notes' ? $response->withHeader('X-Sample', 'seen') : $response;
            }
        }];
    }

    #[Override]
    public function permissions(): array
    {
        return ['sample.read' => 'Read the sample notes'];
    }
}
