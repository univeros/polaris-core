<?php

declare(strict_types=1);

namespace Polaris\Messaging;

use Polaris\Messaging\Model\Template;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

/**
 * The one table the plugin owns.
 */
final class Schema
{
    public const string TEMPLATES = 'polaris_messaging_template';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::TEMPLATES, Template::class, [
                Field::string('id', 36)->primary(),
                Field::string('organizationId', 36),
                Field::string('key', 64),
                Field::string('locale', 8),
                Field::string('subject', 255)->nullable(),
                Field::text('text'),
                Field::text('html')->nullable(),
                Field::datetime('updatedAt'),
            ])->unique(['organization_id', 'key', 'locale'], 'polaris_messaging_template_unique'),
        ];
    }
}
