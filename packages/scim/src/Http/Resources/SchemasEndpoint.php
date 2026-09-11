<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Resources;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\Groups;
use Polaris\Scim\Http\ScimEndpoint;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\Users;

/**
 * `GET /scim/v2/{connectionId}/Schemas`: the User and Group schemas, the attributes this server maps.
 */
final class SchemasEndpoint extends ScimEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        $connection = $this->connection($input);
        if (!$connection instanceof Connection) {
            return $connection;
        }
        $location = $this->location($connection) . '/Schemas/';
        $schemas = [
            [
                'id' => Users::SCHEMA,
                'name' => 'User',
                'description' => 'A member of the organization',
                'attributes' => [
                    self::attribute('userName', 'string', required: true, uniqueness: 'server', description: 'The member\'s email address'),
                    self::attribute('displayName', 'string'),
                    self::attribute('externalId', 'string'),
                    self::attribute('active', 'boolean'),
                    ['name' => 'name', 'type' => 'complex', 'multiValued' => false, 'required' => false, 'mutability' => 'readWrite', 'returned' => 'default', 'subAttributes' => [self::attribute('formatted', 'string'), self::attribute('givenName', 'string'), self::attribute('familyName', 'string')]],
                    ['name' => 'emails', 'type' => 'complex', 'multiValued' => true, 'required' => false, 'mutability' => 'readWrite', 'returned' => 'default', 'subAttributes' => [self::attribute('value', 'string'), self::attribute('primary', 'boolean')]],
                    ['name' => 'groups', 'type' => 'complex', 'multiValued' => true, 'required' => false, 'mutability' => 'readOnly', 'returned' => 'default', 'subAttributes' => [self::attribute('value', 'string'), self::attribute('display', 'string')]],
                ],
                'meta' => ['resourceType' => 'Schema', 'location' => $location . Users::SCHEMA],
            ],
            [
                'id' => Groups::SCHEMA,
                'name' => 'Group',
                'description' => 'A role of the organization',
                'attributes' => [
                    self::attribute('displayName', 'string', required: true, uniqueness: 'server'),
                    self::attribute('externalId', 'string'),
                    ['name' => 'members', 'type' => 'complex', 'multiValued' => true, 'required' => false, 'mutability' => 'readWrite', 'returned' => 'default', 'subAttributes' => [self::attribute('value', 'string'), self::attribute('display', 'string')]],
                ],
                'meta' => ['resourceType' => 'Schema', 'location' => $location . Groups::SCHEMA],
            ],
        ];

        return $this->page(['total' => 2, 'resources' => $schemas], 1);
    }

    /**
     * @return array<string, mixed>
     */
    private static function attribute(string $name, string $type, bool $required = false, string $uniqueness = 'none', string $description = ''): array
    {
        return ['name' => $name, 'type' => $type, 'multiValued' => false, 'required' => $required, 'caseExact' => false, 'mutability' => 'readWrite', 'returned' => 'default', 'uniqueness' => $uniqueness, 'description' => $description];
    }
}
