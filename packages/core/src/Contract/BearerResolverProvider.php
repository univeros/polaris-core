<?php

declare(strict_types=1);

namespace Polaris\Contract;

use Polaris\Wiring\Graph;

/**
 * A plugin that authenticates requests of its own kind on core's bearer routes: the pipeline asks its
 * resolvers on the first request that needs them. Built with the graph, so a resolver may use the
 * plugin's own services.
 */
interface BearerResolverProvider
{
    /**
     * @return list<BearerResolver>
     */
    public function bearerResolvers(Graph $graph): array;
}
