<?php

declare(strict_types=1);

namespace Polaris\Tests\Schema;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Model\User;
use Polaris\Schema\Field;
use Polaris\Schema\FieldType;
use Polaris\Schema\Model;
use Polaris\Schema\Schema;

use function array_map;
use function array_unique;
use function class_exists;
use function count;
use function property_exists;

#[CoversClass(Schema::class)]
#[CoversClass(Model::class)]
#[CoversClass(Field::class)]
final class SchemaTest extends TestCase
{
    public function testEveryModelIsDefinedOnceWithAPrimaryKeyAndUniqueColumns(): void
    {
        $models = Schema::all();

        self::assertCount(15, $models);
        self::assertCount(15, array_unique(array_map(static fn(Model $m): string => $m->table, $models)));
        foreach ($models as $model) {
            self::assertTrue(class_exists($model->class), $model->class);
            self::assertNotEmpty($model->primaryKey(), "$model->table needs a primary key");
            $columns = array_map(static fn(Field $f): string => $f->column, $model->fields);
            self::assertSame(count($columns), count(array_unique($columns)), "$model->table has duplicate columns");
            self::assertSame($model, Schema::for($model->class));
        }
    }

    public function testFieldsMatchTheModelClassProperties(): void
    {
        foreach (Schema::all() as $model) {
            $instance = new ($model->class)();
            foreach ($model->fields as $field) {
                self::assertTrue(property_exists($instance, $field->property), "$model->class::\$$field->property");
                self::assertSame($field->property, $model->propertyOf($field->column));
                self::assertSame($field->column, $model->columnOf($field->property));
                if ($field->hasDefault) {
                    self::assertSame($field->default, $instance->{$field->property}, "$model->class::\$$field->property default");
                }
            }
        }
    }

    public function testUserSchemaCarriesTypesLengthsAndIndexes(): void
    {
        $users = Schema::for(User::class);

        self::assertSame('auth_users', $users->table);
        self::assertSame(FieldType::String, $users->field('email')->type);
        self::assertSame(320, $users->field('email')->length);
        self::assertSame('email_verified_at', $users->columnOf('emailVerifiedAt'));
        self::assertTrue($users->field('emailVerifiedAt')->nullable);
        self::assertSame(FieldType::DateTime, $users->field('createdAt')->type);
        self::assertTrue($users->field('id')->primary);
        self::assertSame(['email'], $users->indexes[0]->columns);
        self::assertTrue($users->indexes[0]->unique);
    }

    public function testFieldFluentMethodsReturnCopies(): void
    {
        $field = Field::string('displayName', 120);
        $nullable = $field->nullable();

        self::assertFalse($field->nullable);
        self::assertTrue($nullable->nullable);
        self::assertSame('display_name', $field->column);
    }
}
