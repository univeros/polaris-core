<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\Discovery;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /.well-known/agent-configuration`: the discovery document of the agent protocol.
 */
final class ConfigurationEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Discovery $discovery)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        return new Result(200, $this->discovery->document(), ['Cache-Control' => 'public, max-age=3600']);
    }
}
