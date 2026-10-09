<?php

declare(strict_types=1);

namespace Polaris\Username;

use Polaris\Schema\Field;
use Polaris\Schema\Model;
use Polaris\Username\Model\Username;

/**
 * The table the plugin owns: one username per user, unique in its lowercased form.
 */
final class Schema
{
    public const string USERNAMES = 'polaris_username';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::USERNAMES, Username::class, [
                Field::string('userId', 36)->primary(),
                Field::string('username', 64),
                Field::string('displayUsername', 64),
                Field::datetime('createdAt'),
                Field::datetime('updatedAt'),
            ])->unique(['username'], 'polaris_username_unique'),
        ];
    }
}
