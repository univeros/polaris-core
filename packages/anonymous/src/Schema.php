<?php

declare(strict_types=1);

namespace Polaris\Anonymous;

use Polaris\Anonymous\Model\Guest;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

/**
 * The table the plugin owns: which core users are guests, and the account each was converted into.
 */
final class Schema
{
    public const string GUESTS = 'polaris_anonymous';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::GUESTS, Guest::class, [
                Field::string('userId', 36)->primary(),
                Field::datetime('createdAt'),
                Field::datetime('convertedAt')->nullable(),
                Field::string('convertedUserId', 36)->nullable(),
            ])->index(['created_at'], 'polaris_anonymous_created_index'),
        ];
    }
}
