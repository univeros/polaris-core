<?php

declare(strict_types=1);

namespace Polaris\Scim\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Scim\Filter;
use Polaris\Scim\Patch;
use Polaris\Scim\ScimError;

/**
 * The filter subset and the PatchOp parsing.
 */
#[CoversClass(Filter::class)]
#[CoversClass(Patch::class)]
#[CoversClass(ScimError::class)]
final class FilterAndPatchTest extends TestCase
{
    public function testFiltersParseAndMatch(): void
    {
        $filter = Filter::parse('userName eq "Ada@Example.com" and displayName co "ada" and externalId sw "ext-"');
        self::assertCount(3, $filter->clauses);
        self::assertSame('Ada@Example.com', $filter->equals('username'));
        self::assertNull($filter->equals('externalid'));
        self::assertTrue($filter->matches(['username' => 'ada@example.com', 'displayname' => 'Ada Lovelace', 'externalid' => 'ext-1']));
        self::assertFalse($filter->matches(['username' => 'ada@example.com', 'displayname' => 'Ada Lovelace', 'externalid' => 'other']));
        self::assertTrue(Filter::parse('emails[type eq "work"].value eq "ada@example.com"')->matches(['emails' => ['ada@example.com']]));
        self::assertTrue(Filter::parse('active eq "true"')->matches(['active' => 'true']));
        self::assertTrue(Filter::parse(null)->isEmpty());
        self::assertTrue(Filter::parse('')->matches([]));
        self::assertSame('a "quoted" one', Filter::parse('displayName eq "a \"quoted\" one"')->clauses[0][2]);
        foreach (['userName pr', 'userName eq ada', 'userName gt "a"', 'userName eq "a" or displayName eq "b"', 'garbage'] as $bad) {
            try {
                Filter::parse($bad);
                self::fail($bad . ' parsed');
            } catch (ScimError $error) {
                self::assertSame([400, ScimError::INVALID_FILTER], [$error->status, $error->scimType], $bad);
            }
        }
    }

    public function testPatchOperationsParseAndExposeScalars(): void
    {
        $operations = Patch::operations(['schemas' => [Patch::SCHEMA], 'Operations' => [
            ['op' => 'Replace', 'path' => 'active', 'value' => false],
            ['op' => 'add', 'value' => ['userName' => 'bob@example.com', 'name' => ['givenName' => 'Bob'], 'urn:ietf:params:scim:schemas:core:2.0:User:displayName' => 'Bobby']],
            ['op' => 'remove', 'path' => 'members[value eq "u1"]'],
        ]]);
        self::assertSame(['replace', 'active', false], $operations[0]);
        self::assertFalse(Patch::scalar($operations[0], 'active'));
        self::assertNull(Patch::scalar($operations[0], 'userName'));
        self::assertSame('bob@example.com', Patch::scalar($operations[1], 'userName'));
        self::assertSame('Bob', Patch::scalar($operations[1], 'name.givenName'));
        self::assertSame('Bobby', Patch::scalar($operations[1], 'displayName'));
        self::assertNull(Patch::scalar($operations[1], 'name.familyName'));
        self::assertSame(['remove', 'members[value eq "u1"]', null], $operations[2]);
        self::assertSame('displayName', Patch::stripUrn('urn:ietf:params:scim:schemas:core:2.0:Group:displayName'));
        foreach ([[], ['schemas' => [Patch::SCHEMA]], ['schemas' => [Patch::SCHEMA], 'Operations' => [['op' => 'merge']]], ['schemas' => [Patch::SCHEMA], 'Operations' => [['op' => 'add', 'value' => 'flat']]], ['schemas' => [Patch::SCHEMA], 'Operations' => [['op' => 'add', 'path' => '???', 'value' => 1]]]] as $bad) {
            try {
                Patch::operations($bad);
                self::fail('parsed');
            } catch (ScimError $error) {
                self::assertSame(400, $error->status);
            }
        }
    }
}
