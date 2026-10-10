<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Closure;
use LogicException;

use function in_array;
use function is_array;
use function is_callable;
use function is_string;
use function mb_strlen;
use function preg_match;
use function sprintf;

/**
 * One capability a host declares in the plugin's configuration: what agents may ask to do, the JSON
 * Schema of its arguments, the permission its owner must hold, its risk tier (which decides the
 * approval strength and auto-approval), and where it runs: a `handler` called by `POST /agents/execute`
 * (and by the MCP tool), or a `location`, a host URL guarded by `AgentRequestMiddleware`.
 */
final readonly class Capability
{
    /** @var (Closure(array<string, mixed>, ExecutionContext): mixed)|null */
    public ?Closure $handler;

    /**
     * @param array<string, mixed> $input a JSON Schema (draft 2020-12) of the arguments
     * @param (callable(array<string, mixed>, ExecutionContext): mixed)|null $handler
     */
    public function __construct(
        public string $name,
        public string $description,
        public array $input,
        public string $permission,
        public string $risk = Settings::RISK_MEDIUM,
        public ?string $location = null,
        ?callable $handler = null,
    ) {
        if (preg_match('/^[a-z][a-z0-9_.:-]{0,79}$/', $name) !== 1) {
            throw new LogicException(sprintf('A capability name is lower-case, starts with a letter and is at most 80 characters ("%s").', $name));
        }
        if ($description === '' || mb_strlen($description) > 500) {
            throw new LogicException(sprintf('Capability "%s" needs a description of at most 500 characters.', $name));
        }
        if (preg_match('/^[a-z][a-z0-9_.-]{0,79}$/', $permission) !== 1) {
            throw new LogicException(sprintf('Capability "%s": the permission is a catalog name such as "billing.refund".', $name));
        }
        if (!in_array($risk, Settings::RISKS, true)) {
            throw new LogicException(sprintf('Capability "%s": risk is low, medium or high.', $name));
        }
        if ($location !== null && preg_match('~^https?://[^\s?#]+$~', $location) !== 1) {
            throw new LogicException(sprintf('Capability "%s": location is an absolute http(s) URL without a query.', $name));
        }
        if (($location === null) === ($handler === null)) {
            throw new LogicException(sprintf('Capability "%s" needs exactly one of a location or a handler.', $name));
        }
        $this->handler = $handler === null ? null : $handler(...);
    }

    /**
     * @param array<string, mixed> $definition the keys of the constructor; `input` defaults to any object
     */
    public static function fromArray(array $definition): self
    {
        $name = is_string($definition['name'] ?? null) ? $definition['name'] : '';
        $input = $definition['input'] ?? ['type' => 'object'];
        if (!is_array($input)) {
            throw new LogicException(sprintf('Capability "%s": input is a JSON Schema object.', $name));
        }
        $handler = $definition['handler'] ?? null;
        if ($handler !== null && !is_callable($handler)) {
            throw new LogicException(sprintf('Capability "%s": handler is callable.', $name));
        }

        return new self(
            $name,
            is_string($definition['description'] ?? null) ? $definition['description'] : '',
            $input,
            is_string($definition['permission'] ?? null) ? $definition['permission'] : '',
            is_string($definition['risk'] ?? null) ? $definition['risk'] : Settings::RISK_MEDIUM,
            is_string($definition['location'] ?? null) ? $definition['location'] : null,
            $handler,
        );
    }

    /**
     * The capability as `GET /agents/capabilities` and the discovery document show it (AAP's object plus
     * `permission` and `risk`).
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $out = ['name' => $this->name, 'description' => $this->description, 'input' => $this->input, 'permission' => $this->permission, 'risk' => $this->risk];
        if ($this->location !== null) {
            $out['location'] = $this->location;
        }

        return $out;
    }
}
