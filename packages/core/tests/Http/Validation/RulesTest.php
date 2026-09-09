<?php

declare(strict_types=1);

namespace Polaris\Tests\Http\Validation;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Http\Manifest\FieldSpec;
use Polaris\Http\Validation\Rule;
use Polaris\Http\Validation\Rules;

#[CoversClass(Rule::class)]
#[CoversClass(Rules::class)]
final class RulesTest extends TestCase
{
    public function testParsesEveryRuleFormTheSpecsUse(): void
    {
        foreach (['required', 'optional', 'string', 'email', 'max:320', 'in:recovery,totp', 'regex:/^[a-z0-9-]+$/', 'password_policy', 'e164', 'suspended'] as $rule) {
            self::assertInstanceOf(Rule::class, Rule::parse($rule));
        }
        self::assertSame('320', Rule::parse('max:320')->argument);

        $this->expectException(InvalidArgumentException::class);
        Rule::parse('between:1,2');
    }

    public function testEvaluatesRulesAgainstData(): void
    {
        $fields = [
            new FieldSpec('email', 'string', [Rule::parse('required'), Rule::parse('email'), Rule::parse('max:320')], false),
            new FieldSpec('password', 'string', [Rule::parse('required'), Rule::parse('password_policy')], true),
            new FieldSpec('display_name', 'string', [Rule::parse('optional'), Rule::parse('max:5')], false),
            new FieldSpec('type', 'string', [Rule::parse('required'), Rule::parse('in:totp,sms')], false),
            new FieldSpec('phone', 'string', [Rule::parse('optional'), Rule::parse('e164')], false),
            new FieldSpec('slug', 'string', [Rule::parse('optional'), Rule::parse('regex:/^[a-z0-9-]+$/')], false),
        ];

        self::assertSame([], Rules::violations($fields, ['email' => 'ada@example.com', 'password' => 'x', 'type' => 'totp', 'phone' => '+15551234567', 'slug' => 'acme']));
        self::assertSame(
            ['email must be a valid email address.', 'password is required.', 'display_name must be at most 5 characters.', 'type must be one of totp,sms.', 'phone must be an E.164 phone number.', 'slug has an invalid format.'],
            Rules::violations($fields, ['email' => 'nope', 'display_name' => 'toolong', 'type' => 'push', 'phone' => '555', 'slug' => 'Not Ok']),
        );
    }
}
