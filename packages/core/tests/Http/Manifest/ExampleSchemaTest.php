<?php

declare(strict_types=1);

namespace Polaris\Tests\Http\Manifest;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Http\Manifest\ExampleSchema;

#[CoversClass(ExampleSchema::class)]
final class ExampleSchemaTest extends TestCase
{
    public function testScalarsAndNestedObjectsTakeTheirJsonTypesAndEveryKeyIsRequired(): void
    {
        $schema = ExampleSchema::fromValue(['data' => ['id' => '018f', 'expires_in' => 900, 'ratio' => 0.5, 'verified' => true, 'label' => null]]);

        self::assertSame([
            'type' => 'object',
            'properties' => ['data' => [
                'type' => 'object',
                'properties' => [
                    'id' => ['type' => 'string'],
                    'expires_in' => ['type' => 'integer'],
                    'ratio' => ['type' => 'number'],
                    'verified' => ['type' => 'boolean'],
                    'label' => ['type' => ['string', 'null']],
                ],
                'required' => ['id', 'expires_in', 'ratio', 'verified', 'label'],
            ]],
            'required' => ['data'],
        ], $schema);
    }

    public function testArrayItemsAreMergedWithOptionalAndNullableKeys(): void
    {
        $schema = ExampleSchema::fromValue([
            ['id' => 'a', 'type' => 'totp', 'label' => 'Phone', 'email' => 'a@example.com', 'roles' => []],
            ['id' => 'b', 'type' => 'sms', 'destination' => '+1', 'email' => null, 'roles' => ['owner']],
        ]);

        self::assertSame([
            'type' => 'array',
            'items' => [
                'type' => 'object',
                'properties' => [
                    'id' => ['type' => 'string'],
                    'type' => ['type' => 'string'],
                    'label' => ['type' => 'string'],
                    'email' => ['type' => ['null', 'string']],
                    'roles' => ['type' => 'array', 'items' => ['type' => 'string']],
                    'destination' => ['type' => 'string'],
                ],
                'required' => ['id', 'type', 'email', 'roles'],
            ],
        ], $schema);
    }

    public function testEmptyArraysAndDisagreeingShapesAreUntyped(): void
    {
        self::assertSame(['type' => 'array', 'items' => []], ExampleSchema::fromValue([]));
        self::assertSame(['type' => 'array', 'items' => []], ExampleSchema::fromValue([['a' => 1], 'b']));
        self::assertSame(['type' => 'array', 'items' => ['type' => ['integer', 'string']]], ExampleSchema::fromValue([1, 'b']));
    }

    public function testSeveralExamplesBecomeAOneOf(): void
    {
        $schema = ExampleSchema::fromExamples(['example' => ['data' => ['token' => 'x']], 'example_mfa' => ['data' => ['mfa_required' => true]]]);

        self::assertArrayHasKey('oneOf', $schema);
        self::assertCount(2, $schema['oneOf']);
        self::assertSame(['type' => 'boolean'], $schema['oneOf'][1]['properties']['data']['properties']['mfa_required']);
    }
}
