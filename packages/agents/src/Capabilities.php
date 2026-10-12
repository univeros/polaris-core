<?php

declare(strict_types=1);

namespace Polaris\Agents;

use LogicException;

use function array_keys;
use function array_values;
use function sprintf;

/**
 * The capabilities the host configured, by name and by location.
 */
final class Capabilities
{
    /** @var array<string, Capability> */
    private array $byName = [];
    /** @var array<string, Capability> normalised location (host and path, {@see Url::route()}) => capability */
    private array $byLocation = [];

    /**
     * @param list<Capability|array<string, mixed>> $capabilities
     */
    public function __construct(array $capabilities)
    {
        foreach ($capabilities as $capability) {
            $capability = $capability instanceof Capability ? $capability : Capability::fromArray($capability);
            if (isset($this->byName[$capability->name])) {
                throw new LogicException(sprintf('Capability "%s" is declared twice.', $capability->name));
            }
            $this->byName[$capability->name] = $capability;
            if ($capability->location !== null) {
                $location = Url::route($capability->location);
                if (isset($this->byLocation[$location])) {
                    throw new LogicException(sprintf('Two capabilities share the location %s.', $location));
                }
                $this->byLocation[$location] = $capability;
            }
        }
    }

    public function find(string $name): ?Capability
    {
        return $this->byName[$name] ?? null;
    }

    /**
     * The capability a request URL is the location of: host, port and path compared normalised
     * ({@see Url}), whatever the scheme, so no spelling of the location passes unguarded.
     */
    public function atLocation(string $url): ?Capability
    {
        return $this->byLocation[Url::route($url)] ?? null;
    }

    /**
     * @return list<Capability>
     */
    public function all(): array
    {
        return array_values($this->byName);
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->byName);
    }

    /**
     * The permissions the capabilities require, deduplicated, for the permission catalog.
     *
     * @return array<string, string> permission => description
     */
    public function permissions(): array
    {
        $permissions = [];
        foreach ($this->byName as $capability) {
            $permissions[$capability->permission] ??= sprintf('Required by the agent capability "%s"', $capability->name);
        }

        return $permissions;
    }
}
