<?php

declare(strict_types=1);

namespace Polaris\Mcp\Server;

use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Http\Manifest\Manifest;
use Polaris\Http\Manifest\OpenApi;

use function is_array;
use function preg_replace;
use function sprintf;
use function str_replace;
use function strtolower;

/**
 * A manifest route as an MCP tool's schemas: the name (`polaris.` plus the spec file's path under
 * `api/`, `/` and `-` read as `.`: `orgs/members-list.yaml` is `polaris.orgs.members.list`), the
 * input schema (the route's OpenAPI operation folded into one object: path parameters, query
 * parameters and body properties), the output schema (`{status, body}`, the body typed from the
 * spec's example as the OpenAPI document types it).
 */
final class ToolSchema
{
    public const string PREFIX = 'polaris.';

    /** @var array<string, array<string, mixed>> */
    private readonly array $paths;

    public function __construct(Manifest $manifest)
    {
        /** @var array<string, array<string, mixed>> $paths */
        $paths = OpenApi::document($manifest)['paths'];
        $this->paths = $paths;
    }

    public static function name(EndpointSpec $spec): string
    {
        $file = (string) preg_replace('/\.ya?ml$/', '', $spec->file);

        return self::PREFIX . str_replace(['/', '-'], '.', $file);
    }

    public static function description(EndpointSpec $spec): string
    {
        return sprintf('%s (%s)', $spec->summary !== '' ? $spec->summary : $spec->route(), $spec->route());
    }

    /**
     * @return array<string, mixed>
     */
    public function input(EndpointSpec $spec): array
    {
        $operation = $this->operation($spec);
        $properties = [];
        $required = [];
        foreach (is_array($operation['parameters'] ?? null) ? $operation['parameters'] : [] as $parameter) {
            if (!is_array($parameter) || !isset($parameter['name'])) {
                continue;
            }
            $schema = is_array($parameter['schema'] ?? null) ? $parameter['schema'] : ['type' => 'string'];
            $properties[(string) $parameter['name']] = [...$schema, 'description' => sprintf('%s parameter', (string) ($parameter['in'] ?? 'query'))];
            if (($parameter['required'] ?? false) === true) {
                $required[] = (string) $parameter['name'];
            }
        }
        $body = $operation['requestBody']['content']['application/json']['schema'] ?? null;
        if (is_array($body)) {
            foreach (is_array($body['properties'] ?? null) ? $body['properties'] : [] as $name => $schema) {
                $properties[(string) $name] = $schema;
            }
            foreach (is_array($body['required'] ?? null) ? $body['required'] : [] as $name) {
                $required[] = (string) $name;
            }
        }
        $schema = ['type' => 'object', 'properties' => $properties];
        if ($required !== []) {
            $schema['required'] = $required;
        }

        return $schema;
    }

    /**
     * @return array<string, mixed>
     */
    public function output(EndpointSpec $spec): array
    {
        $status = (string) ($spec->outputStatus ?? 200);
        $body = $this->operation($spec)['responses'][$status]['content']['application/json']['schema'] ?? null;

        return [
            'type' => 'object',
            'properties' => [
                'status' => ['type' => 'integer', 'description' => 'The HTTP status the route answered'],
                'body' => is_array($body) ? $body : ['description' => 'The response body'],
            ],
            'required' => ['status', 'body'],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function operation(EndpointSpec $spec): array
    {
        $operation = $this->paths[$spec->path][strtolower($spec->method)] ?? null;

        return is_array($operation) ? $operation : [];
    }
}
