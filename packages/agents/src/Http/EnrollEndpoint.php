<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\Hosts;
use Polaris\Agents\Registrations;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Psr\Http\Message\ServerRequestInterface;

use function preg_match;

/**
 * `POST /agents/enroll`: a host, with its enrolment token as the bearer, creates an agent under its
 * owner; the host's default capabilities are asked at once.
 */
final class EnrollEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Hosts $hosts, private readonly Registrations $registrations)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $request = $input->attribute(AgentPrincipalMiddleware::REQUEST);
        $authorization = $request instanceof ServerRequestInterface ? $request->getHeaderLine('Authorization') : '';
        $host = preg_match('/^Bearer\s+(\S+)$/i', $authorization, $matches) === 1 ? $this->hosts->authenticate($matches[1]) : null;
        if ($host === null) {
            return $this->refuse(new AgentException(AgentException::UNAUTHORIZED, 'A live host enrolment token (peh_...) is required as the bearer.'));
        }
        $context = $this->client($input);
        try {
            $enrolled = $this->registrations->enroll($host, $input->all(), $context->ip, $context->userAgent);
        } catch (AgentException $exception) {
            return $this->refuse($exception);
        }

        return new Result(201, $this->registrations->response($enrolled), self::NO_STORE);
    }
}
