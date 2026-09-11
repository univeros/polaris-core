<?php

declare(strict_types=1);

namespace Polaris\Http\Manifest;

use Polaris\Http\Validation\Rule;

use function array_map;
use function array_values;
use function count;
use function explode;
use function preg_match_all;
use function sprintf;
use function strtolower;
use function trim;

/**
 * An OpenAPI 3.1 document generated from the manifest: one operation per spec, request bodies
 * and parameters from `input`, security from `auth`, responses from `output` (the success body typed
 * from its example by {@see ExampleSchema}) and `errors`, and the Polaris policy fields as
 * `x-polaris-*` extensions.
 */
final class OpenApi
{
    private const string ERROR_SCHEMA = '#/components/schemas/Error';

    /**
     * @return array<string, mixed>
     */
    public static function document(Manifest $manifest, string $version = '0.2.0'): array
    {
        $paths = [];
        foreach ($manifest->endpoints() as $spec) {
            $paths[$spec->path][strtolower($spec->method)] = self::operation($spec);
        }

        return [
            'openapi' => '3.1.0',
            'info' => ['title' => 'Polaris for PHP', 'version' => $version, 'description' => 'Self-hosted authentication, MFA, organizations and RBAC.'],
            'paths' => $paths,
            'components' => [
                'securitySchemes' => [
                    'bearerAuth' => ['type' => 'http', 'scheme' => 'bearer', 'bearerFormat' => 'JWT'],
                    'mfaToken' => ['type' => 'http', 'scheme' => 'bearer', 'bearerFormat' => 'JWT', 'description' => 'The short-lived login_mfa ticket returned by /auth/login.'],
                ],
                'schemas' => [
                    'Error' => [
                        'type' => 'object',
                        'properties' => ['error' => ['type' => 'string'], 'message' => ['type' => 'string']],
                    ],
                    'ValidationError' => [
                        'type' => 'object',
                        'properties' => ['errors' => ['type' => 'array', 'items' => ['type' => 'string']]],
                    ],
                ],
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function operation(EndpointSpec $spec): array
    {
        $operation = [
            'operationId' => self::operationId($spec),
            'summary' => $spec->summary,
            'tags' => $spec->tags,
            'x-polaris-effect' => $spec->effect,
            'x-polaris-receipt' => $spec->receipt,
        ];
        if ($spec->rateLimit !== null) {
            $operation['x-polaris-rate-limit'] = $spec->rateLimit;
        }
        if ($spec->stepUp) {
            $operation['x-polaris-step-up'] = true;
        }
        if ($spec->requiresPermissions !== []) {
            $operation['x-polaris-requires-permissions'] = $spec->requiresPermissions;
        }
        if ($spec->auth === 'bearer') {
            $operation['security'] = [['bearerAuth' => []]];
        } elseif ($spec->auth === 'mfa_token') {
            $operation['security'] = [['mfaToken' => []]];
        }

        $parameters = [];
        preg_match_all('/\{(\w+)\}/', $spec->path, $matches);
        foreach ($matches[1] as $name) {
            $parameters[] = ['name' => $name, 'in' => 'path', 'required' => true, 'schema' => ['type' => 'string']];
        }
        if ($spec->inputSource === 'query') {
            foreach ($spec->fields as $field) {
                $parameters[] = ['name' => $field->name, 'in' => 'query', 'required' => self::required($field), 'schema' => self::schema($field)];
            }
        }
        if ($parameters !== []) {
            $operation['parameters'] = $parameters;
        }
        if ($spec->inputSource === 'body' && $spec->fields !== []) {
            $properties = [];
            $required = [];
            foreach ($spec->fields as $field) {
                $properties[$field->name] = self::schema($field);
                if (self::required($field)) {
                    $required[] = $field->name;
                }
            }
            $schema = ['type' => 'object', 'properties' => $properties];
            if ($required !== []) {
                $schema['required'] = $required;
            }
            $operation['requestBody'] = ['required' => true, 'content' => ['application/json' => ['schema' => $schema]]];
        }

        $responses = [];
        $status = (string) ($spec->outputStatus ?? 200);
        $responses[$status] = ['description' => 'Success'];
        if ($spec->outputExamples !== []) {
            $content = ['schema' => ExampleSchema::fromExamples($spec->outputExamples)];
            if (count($spec->outputExamples) === 1) {
                $content['example'] = $spec->outputExamples['example'] ?? array_values($spec->outputExamples)[0];
            } else {
                $content['examples'] = array_map(static fn(array $example): array => ['value' => $example], $spec->outputExamples);
            }
            $responses[$status]['content'] = ['application/json' => $content];
        }
        foreach ($spec->errors as $error) {
            $code = (string) $error['status'];
            $description = $error['code'] === null ? 'Error' : $error['code'];
            if (isset($responses[$code])) {
                $responses[$code]['description'] .= ' | ' . $description;
                continue;
            }
            $responses[$code] = [
                'description' => $description,
                'content' => ['application/json' => ['schema' => ['$ref' => $error['status'] === 422 ? '#/components/schemas/ValidationError' : self::ERROR_SCHEMA]]],
            ];
        }
        $operation['responses'] = $responses;

        return $operation;
    }

    private static function required(FieldSpec $field): bool
    {
        foreach ($field->rules as $rule) {
            if ($rule->name === 'required') {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, mixed>
     */
    private static function schema(FieldSpec $field): array
    {
        $schema = ['type' => $field->type === 'integer' ? 'integer' : ($field->type === 'boolean' ? 'boolean' : ($field->type === 'array' ? 'array' : 'string'))];
        foreach ($field->rules as $rule) {
            self::applyRule($schema, $rule);
        }
        if ($field->sensitive) {
            $schema['format'] = $schema['format'] ?? 'password';
            $schema['x-polaris-sensitive'] = true;
        }

        return $schema;
    }

    /**
     * @param array<string, mixed> $schema
     */
    private static function applyRule(array &$schema, Rule $rule): void
    {
        switch ($rule->name) {
            case 'email':
                $schema['format'] = 'email';
                break;
            case 'max':
                $schema['maxLength'] = (int) $rule->argument;
                break;
            case 'in':
                $schema['enum'] = array_map(trim(...), explode(',', (string) $rule->argument));
                break;
            case 'regex':
                $schema['pattern'] = trim((string) $rule->argument, '/');
                break;
            case 'e164':
                $schema['pattern'] = '^\\+[1-9]\\d{1,14}$';
                break;
            case 'password_policy':
                $schema['description'] = 'Must satisfy the configured password policy.';
                break;
        }
    }

    private static function operationId(EndpointSpec $spec): string
    {
        $parts = explode('\\', $spec->class);
        $short = $parts[count($parts) - 1];

        return sprintf('%s_%s', strtolower($spec->method), $short);
    }
}
