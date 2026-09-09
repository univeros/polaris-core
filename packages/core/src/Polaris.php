<?php

declare(strict_types=1);

namespace Polaris;

use Polaris\Http\Manifest\Manifest;
use Polaris\Schema\Model;
use Polaris\Schema\Schema;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;

/**
 * The entry point: `Polaris::create(new Config(...))` builds the whole object graph without a
 * container. HTTP wiring lives in the adapter packages (`polaris/psr15` and later framework
 * adapters), which take the {@see Graph} this facade exposes.
 */
final class Polaris
{
    private function __construct(private readonly Graph $graph)
    {
    }

    public static function create(Config $config): self
    {
        return new self(new Graph($config));
    }

    /**
     * The services: `graph()->tokens()`, `->organizations()`, `->login()`, and so on.
     */
    public function graph(): Graph
    {
        return $this->graph;
    }

    public function manifest(): Manifest
    {
        return $this->graph->manifest();
    }

    /**
     * @return list<Model>
     */
    public function schema(): array
    {
        return Schema::all();
    }
}
