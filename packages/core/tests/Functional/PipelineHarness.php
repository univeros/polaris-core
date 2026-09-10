<?php

declare(strict_types=1);

namespace Polaris\Tests\Functional;

use Laminas\Diactoros\ResponseFactory;
use Override;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The default harness: `Polaris::create()` and the PSR-15 pipeline, no host.
 */
final class PipelineHarness implements Harness
{
    private function __construct(private readonly Graph $graph, private readonly Pipeline $pipeline)
    {
    }

    #[Override]
    public static function create(Config $config): static
    {
        $graph = Polaris::create($config)->graph();

        return new self($graph, new Pipeline($graph, new ResponseFactory()));
    }

    #[Override]
    public function graph(): Graph
    {
        return $this->graph;
    }

    #[Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return $this->pipeline->handle($request);
    }

    #[Override]
    public static function transportHeaders(): array
    {
        return [];
    }
}
