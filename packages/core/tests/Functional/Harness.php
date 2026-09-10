<?php

declare(strict_types=1);

namespace Polaris\Tests\Functional;

use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * What the functional suite runs its requests through. `PipelineHarness` is the bare PSR-15 pipeline;
 * each framework adapter ships one that boots a real application (docs/adapters/spec.md §3.7), selected
 * by the `POLARIS_HARNESS` environment variable, so the same tests and the same contract fixtures prove
 * every host.
 */
interface Harness
{
    /**
     * Boots the host from this Config: the test's database adapter, mailer, SMS sender, dispatcher,
     * secrets and auth settings.
     */
    public static function create(Config $config): static;

    public function graph(): Graph;

    public function handle(ServerRequestInterface $request): ResponseInterface;

    /**
     * Lower-case names of the headers the host's transport layer adds to every response (a computed
     * Cache-Control, for instance); the contract comparison ignores exactly these.
     *
     * @return list<string>
     */
    public static function transportHeaders(): array;
}
