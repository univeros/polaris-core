<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentAuthenticator;
use Polaris\Agents\AgentException;
use Polaris\Agents\Capabilities;
use Polaris\Agents\Grants;
use Polaris\Agents\Model\Grant;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * `GET /agents/capabilities`: every capability (AAP's object plus `permission` and `risk`), with
 * `grant_status` (`active`, `pending`, `none`) when an agent authenticates.
 */
final class CapabilitiesEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Capabilities $capabilities, private readonly AgentAuthenticator $authenticator, private readonly Grants $grants, private readonly ClockInterface $clock)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $request = $input->attribute(AgentPrincipalMiddleware::REQUEST);
        $statuses = null;
        if ($request instanceof ServerRequestInterface && $request->hasHeader('Authorization')) {
            try {
                $agent = $this->authenticator->authenticate($request)->agent;
            } catch (AgentException $exception) {
                return $this->refuse($exception);
            }
            $statuses = [];
            foreach ($this->grants->forAgent($agent) as $grant) {
                if ($grant->isLive($this->clock->now())) {
                    $statuses[$grant->capability] = Grant::STATUS_ACTIVE;
                } elseif ($grant->status === Grant::STATUS_PENDING && ($statuses[$grant->capability] ?? null) !== Grant::STATUS_ACTIVE) {
                    $statuses[$grant->capability] = Grant::STATUS_PENDING;
                }
            }
        }
        $data = [];
        foreach ($this->capabilities->all() as $capability) {
            $item = $capability->toArray();
            if ($statuses !== null) {
                $item['grant_status'] = $statuses[$capability->name] ?? 'none';
            }
            $data[] = $item;
        }

        return new Result(200, ['data' => ['capabilities' => $data, 'next_cursor' => null, 'has_more' => false]], $statuses === null ? ['Cache-Control' => 'public, max-age=300'] : self::NO_STORE);
    }
}
