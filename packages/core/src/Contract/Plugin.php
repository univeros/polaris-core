<?php

declare(strict_types=1);

namespace Polaris\Contract;

use Polaris\Schema\Model;
use Polaris\Wiring\Graph;
use Psr\Http\Server\MiddlewareInterface;

/**
 * A package that extends Polaris from the outside: its own tables, endpoints, services, listeners and
 * permissions, all declared as data and wired by `Polaris::create(new Config(plugins: [...]))`. A plugin
 * owns only the tables it declares and the routes its manifest directory holds; core's contract does not
 * change because a plugin is present.
 *
 * Plugins are known once `Polaris::create()` ran: their models join {@see \Polaris\Schema\Schema::all()},
 * their manifest joins the router, their services resolve endpoint constructor parameters, their
 * listeners are part of `Polaris::listeners()`, their permissions are seeded with the catalog.
 */
interface Plugin extends PermissionContributorInterface
{
    /**
     * A short, stable identifier (`audit`, `admin`); also the subdirectory the plugin's specs live in.
     */
    public function id(): string;

    /**
     * The models the plugin stores; their tables are created, diffed and dropped with core's.
     *
     * @return list<Model>
     */
    public function schema(): array;

    /**
     * The `api/<id>/**\/*.yaml` directory of the plugin's endpoints, or null for a plugin without routes.
     * Static because a host's route table is built before the plugin is configured.
     */
    public static function manifestDirectory(): ?string;

    /**
     * Factories for the services the plugin's endpoints and listeners need, keyed by the class an
     * endpoint constructor asks for; each is built once per graph.
     *
     * @return array<class-string, callable(Graph): object>
     */
    public function services(): array;

    /**
     * Listeners for the host's PSR-14 dispatcher, subscribed with core's through `Polaris::listeners()`.
     *
     * @return list<callable(object): void>
     */
    public function listeners(Graph $graph): array;

    /**
     * PSR-15 middleware for the Polaris pipeline, run on every Polaris route right after the bearer
     * token was parsed and before step-up, denylist and authorization: where a plugin resolves its
     * own principals or adds a header. Core's own middleware stays as it is.
     *
     * @return list<MiddlewareInterface>
     */
    public function middleware(Graph $graph): array;
}
