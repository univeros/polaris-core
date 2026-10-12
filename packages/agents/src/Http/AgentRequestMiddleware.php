<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentAuthenticator;
use Polaris\Agents\AgentException;
use Polaris\Agents\Capabilities;
use Polaris\Agents\Capability;
use Polaris\Agents\ExecutionContext;
use Polaris\Agents\Executor;
use Polaris\Agents\Model\Receipt;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function is_array;
use function json_decode;

/**
 * The host puts it in front of its routes (`AgentsPlugin::of($graph)->requestMiddleware($graph,
 * 'capability')`, bound to the capability of that route, or unbound, matching request URLs against the
 * locations): a request for a capability must authenticate an agent (a JWT whose `aud` is the URL
 * called, or an access token) holding a live grant whose constraints the arguments (the JSON body)
 * satisfy; the budget, the host's handler and the receipt (outcome from the response status) run in
 * one transaction, and the handler reads the evaluated grant from the attribute `polaris.agents.grant`.
 * Unbound, a URL that is no location ({@see Capabilities::atLocation()}) passes through untouched.
 */
final class AgentRequestMiddleware implements MiddlewareInterface
{
    public const string GRANT = 'polaris.agents.grant';
    public const string AGENT = 'polaris.agents.agent';
    public const string CONTEXT = 'polaris.agents.context';

    public function __construct(
        private readonly Capabilities $capabilities,
        private readonly AgentAuthenticator $authenticator,
        private readonly Executor $executor,
        private readonly Problems $problems,
        private readonly ?Capability $bound = null,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $capability = $this->bound ?? $this->capabilities->atLocation((string) $request->getUri());
        if ($capability === null) {
            return $handler->handle($request);
        }
        try {
            $principal = $this->authenticator->authenticate($request);
        } catch (AgentException $exception) {
            return $this->problems->respond($exception);
        }
        try {
            $evaluation = $this->executor->evaluate($principal, $capability->name, self::arguments($request));
        } catch (AgentException $exception) {
            $this->executor->deny($principal, $capability->name, $exception);

            return $this->problems->respond($exception);
        }
        try {
            $execution = $this->executor->run(
                $evaluation,
                static fn(ExecutionContext $context): ResponseInterface => $handler->handle($request->withAttribute(self::GRANT, $context->grant)->withAttribute(self::AGENT, $context->agent)->withAttribute(self::CONTEXT, $context)),
                static fn(mixed $response): string => $response instanceof ResponseInterface && $response->getStatusCode() < 300 ? Receipt::OUTCOME_SUCCESS : Receipt::OUTCOME_FAILED,
            );
        } catch (AgentException $exception) {
            return $this->problems->respond($exception);
        }
        /** @var ResponseInterface $response */
        $response = $execution->result;

        return $response->withHeader('X-Polaris-Receipt', $execution->receipt->id);
    }

    /**
     * The arguments: the parsed body when the host parsed it, else the JSON body.
     *
     * @return array<string, mixed>
     */
    private static function arguments(ServerRequestInterface $request): array
    {
        $parsed = $request->getParsedBody();
        if (is_array($parsed)) {
            return $parsed;
        }
        $body = (string) $request->getBody();
        $request->getBody()->rewind();
        $decoded = $body === '' ? [] : json_decode($body, true);

        return is_array($decoded) ? $decoded : [];
    }
}
