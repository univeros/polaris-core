<?php

declare(strict_types=1);

namespace Polaris\Http\Manifest;

use InvalidArgumentException;
use Polaris\Http\Validation\Rule;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use Symfony\Component\Yaml\Yaml;

use function array_map;
use function array_values;
use function implode;
use function dirname;
use function in_array;
use function is_array;
use function is_bool;
use function is_int;
use function is_string;
use function sort;
use function sprintf;
use function str_ends_with;
use function str_starts_with;
use function strtoupper;
use function substr;

/**
 * Loads and validates the `api/**\/*.yaml` specs into a {@see Manifest}. Structural rules:
 * `endpoint.method`, `endpoint.path`, `endpoint.auth` and `endpoint.effect` are required, as is
 * `domain.class`; every route is unique; every rule parses. Loaded once per process per directory.
 */
final class Loader
{
    /** @var array<string, Manifest> */
    private static array $cache = [];

    /** @var list<string> */
    private readonly array $directories;

    /**
     * Core's `api/` and, after it, each plugin's directory; routes must be unique across all of them.
     */
    public function __construct(string $directory, string ...$more)
    {
        $this->directories = [$directory, ...array_values($more)];
    }

    public static function defaultDirectory(): string
    {
        return dirname(__DIR__, 3) . '/api';
    }

    public function load(): Manifest
    {
        return self::$cache[implode("\n", $this->directories)] ??= new Manifest($this->read());
    }

    /**
     * @return list<EndpointSpec>
     */
    private function read(): array
    {
        $endpoints = [];
        $routes = [];
        foreach ($this->directories as $directory) {
            $files = [];
            foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory)) as $file) {
                if ($file instanceof SplFileInfo && str_ends_with($file->getFilename(), '.yaml')) {
                    $files[] = $file->getPathname();
                }
            }
            sort($files);
            foreach ($files as $file) {
                $spec = $this->parse($directory, $file);
                if (isset($routes[$spec->route()])) {
                    throw new InvalidArgumentException(sprintf('%s declares route %s already declared by %s.', $spec->file, $spec->route(), $routes[$spec->route()]));
                }
                $routes[$spec->route()] = $spec->file;
                $endpoints[] = $spec;
            }
        }

        return $endpoints;
    }

    private function parse(string $directory, string $file): EndpointSpec
    {
        $name = substr($file, strlen($directory) + 1);
        $document = Yaml::parseFile($file);
        if (!is_array($document)) {
            throw new InvalidArgumentException(sprintf('%s is not a spec document.', $name));
        }
        $endpoint = $this->section($document, 'endpoint', $name);
        $domain = $this->section($document, 'domain', $name);
        $input = is_array($document['input'] ?? null) ? $document['input'] : ['source' => 'none'];
        $output = is_array($document['output'] ?? null) ? $document['output'] : [];

        $method = strtoupper($this->string($endpoint, 'method', $name));
        $auth = $this->string($endpoint, 'auth', $name);
        $effect = $this->string($endpoint, 'effect', $name);
        $source = is_string($input['source'] ?? null) ? $input['source'] : 'none';
        if (!in_array($auth, EndpointSpec::AUTH, true)) {
            throw new InvalidArgumentException(sprintf('%s: unknown auth "%s".', $name, $auth));
        }
        if (!in_array($effect, EndpointSpec::EFFECTS, true)) {
            throw new InvalidArgumentException(sprintf('%s: unknown effect "%s".', $name, $effect));
        }
        if (!in_array($source, EndpointSpec::SOURCES, true)) {
            throw new InvalidArgumentException(sprintf('%s: unknown input source "%s".', $name, $source));
        }
        $class = $this->string($domain, 'class', $name);
        if (!class_exists($class)) {
            throw new InvalidArgumentException(sprintf('%s: endpoint class %s does not exist.', $name, $class));
        }

        $receipt = $endpoint['receipt'] ?? ($effect !== 'read');

        return new EndpointSpec(
            file: $name,
            method: $method,
            path: $this->string($endpoint, 'path', $name),
            summary: is_string($endpoint['summary'] ?? null) ? $endpoint['summary'] : '',
            tags: $this->strings($endpoint['tags'] ?? []),
            auth: $auth,
            rateLimit: is_string($endpoint['rate_limit'] ?? null) ? $endpoint['rate_limit'] : null,
            effect: $effect,
            receipt: is_bool($receipt) ? $receipt : (bool) $receipt,
            stepUp: (bool) ($endpoint['step_up'] ?? false),
            requiresPermissions: $this->strings($endpoint['requires_permissions'] ?? []),
            inputSource: $source,
            fields: $this->fields(is_array($input['fields'] ?? null) ? $input['fields'] : [], $name),
            class: $class,
            outputStatus: is_int($output['status'] ?? null) ? $output['status'] : null,
            outputExamples: $this->examples($output),
            errors: $this->errors($document['errors'] ?? [], $name),
            events: $this->strings($document['events'] ?? []),
            plugin: $directory === $this->directories[0] ? null : explode('/', $name)[0],
        );
    }

    /**
     * The response bodies a spec shows: `example` and any `example_<variant>` (login's `example_mfa_required`).
     *
     * @param array<string, mixed> $output
     * @return array<string, array<string, mixed>>
     */
    private function examples(array $output): array
    {
        $examples = [];
        foreach ($output as $key => $value) {
            if (($key === 'example' || str_starts_with($key, 'example_')) && is_array($value)) {
                $examples[$key] = $value;
            }
        }

        return $examples;
    }

    /**
     * @param array<string, mixed> $document
     * @return array<string, mixed>
     */
    private function section(array $document, string $key, string $file): array
    {
        $section = $document[$key] ?? null;
        if (!is_array($section)) {
            throw new InvalidArgumentException(sprintf('%s: missing "%s" section.', $file, $key));
        }

        return $section;
    }

    /**
     * @param array<string, mixed> $section
     */
    private function string(array $section, string $key, string $file): string
    {
        $value = $section[$key] ?? null;
        if (!is_string($value) || $value === '') {
            throw new InvalidArgumentException(sprintf('%s: "%s" is required.', $file, $key));
        }

        return $value;
    }

    /**
     * @return list<string>
     */
    private function strings(mixed $values): array
    {
        return is_array($values) ? array_values(array_map(static fn(mixed $v): string => (string) $v, $values)) : [];
    }

    /**
     * @param array<string, mixed> $fields
     * @return list<FieldSpec>
     */
    private function fields(array $fields, string $file): array
    {
        $specs = [];
        foreach ($fields as $fieldName => $definition) {
            if (!is_array($definition)) {
                throw new InvalidArgumentException(sprintf('%s: field "%s" must be a map.', $file, (string) $fieldName));
            }
            $rules = [];
            foreach ($this->strings($definition['rules'] ?? []) as $rule) {
                $rules[] = Rule::parse($rule);
            }
            $specs[] = new FieldSpec(
                (string) $fieldName,
                is_string($definition['type'] ?? null) ? $definition['type'] : 'string',
                $rules,
                (bool) ($definition['sensitive'] ?? false),
            );
        }

        return $specs;
    }

    /**
     * @return list<array{status: int, code: string|null}>
     */
    private function errors(mixed $errors, string $file): array
    {
        $list = [];
        foreach (is_array($errors) ? $errors : [] as $error) {
            $code = $error['code'] ?? null;
            if (!is_array($error) || !is_int($error['status'] ?? null) || ($code !== null && !is_string($code))) {
                throw new InvalidArgumentException(sprintf('%s: every error needs a status and a code (null for a codeless body).', $file));
            }
            $list[] = ['status' => $error['status'], 'code' => $code];
        }

        return $list;
    }
}
