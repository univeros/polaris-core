<?php

declare(strict_types=1);

namespace Polaris\Scim;

use function array_key_exists;
use function explode;
use function in_array;
use function is_array;
use function is_string;
use function preg_match;
use function strtolower;

/**
 * A PATCH request (RFC 7644 §3.5.2): `Operations` of `add`, `replace`, `remove` with a `path` (or the
 * value's keys when there is none), applied to a flat representation of a resource.
 */
final class Patch
{
    public const string SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

    /**
     * The operations as `[op, path (lower-case, or null), value]`.
     *
     * @param array<string, mixed> $body
     * @return list<array{string, string|null, mixed}>
     * @throws ScimError
     */
    public static function operations(array $body): array
    {
        $schemas = $body['schemas'] ?? [];
        if (!is_array($schemas) || !in_array(self::SCHEMA, $schemas, true)) {
            throw ScimError::invalid('A PATCH carries the PatchOp schema.', ScimError::INVALID_SYNTAX);
        }
        $operations = $body['Operations'] ?? null;
        if (!is_array($operations) || $operations === []) {
            throw ScimError::invalid('A PATCH carries at least one operation.', ScimError::INVALID_SYNTAX);
        }
        $parsed = [];
        foreach ($operations as $operation) {
            $operation = is_array($operation) ? $operation : [];
            $op = is_string($operation['op'] ?? null) ? strtolower($operation['op']) : '';
            if (!in_array($op, ['add', 'replace', 'remove'], true)) {
                throw ScimError::invalid('op must be add, replace or remove.', ScimError::INVALID_SYNTAX);
            }
            $path = is_string($operation['path'] ?? null) && $operation['path'] !== '' ? $operation['path'] : null;
            if ($path !== null && preg_match('/^[A-Za-z][A-Za-z0-9_.:]*(\[[^\]]*\])?(\.[A-Za-z]+)?$/', $path) !== 1) {
                throw ScimError::invalid('The path is not supported.', ScimError::INVALID_PATH);
            }
            if ($path === null && $op !== 'remove' && !is_array($operation['value'] ?? null)) {
                throw ScimError::invalid('An operation without a path takes an object value.', ScimError::INVALID_VALUE);
            }
            $parsed[] = [$op, $path, array_key_exists('value', $operation) ? $operation['value'] : null];
        }

        return $parsed;
    }

    /**
     * The scalar the operation sets for `$attribute` (`active`, `userName`, `name.givenName`), whether
     * given as the path or as a key of a path-less value; null when the operation does not touch it.
     *
     * @param array{string, string|null, mixed} $operation
     */
    public static function scalar(array $operation, string $attribute): mixed
    {
        [, $path, $value] = $operation;
        $attribute = strtolower($attribute);
        if ($path !== null) {
            return strtolower(self::stripUrn($path)) === $attribute ? $value : null;
        }
        if (!is_array($value)) {
            return null;
        }
        $segments = explode('.', $attribute);
        foreach ($value as $key => $candidate) {
            if (!is_string($key)) {
                continue;
            }
            $key = strtolower(self::stripUrn($key));
            if ($key === $attribute) {
                return $candidate;
            }
            if (count($segments) === 2 && $key === $segments[0] && is_array($candidate)) {
                foreach ($candidate as $sub => $inner) {
                    if (is_string($sub) && strtolower($sub) === $segments[1]) {
                        return $inner;
                    }
                }
            }
        }

        return null;
    }

    public static function stripUrn(string $path): string
    {
        $colon = strrpos($path, ':');

        return $colon === false ? $path : substr($path, $colon + 1);
    }
}
