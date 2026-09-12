<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Resources;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\Http\ScimEndpoint;
use Polaris\Scim\Model\Connection;

/**
 * `GET /scim/v2/{connectionId}/ServiceProviderConfig`: what this server supports.
 */
final class ServiceProviderConfigEndpoint extends ScimEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        $connection = $this->connection($input);
        if (!$connection instanceof Connection) {
            return $connection;
        }

        return $this->scim(200, [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
            'patch' => ['supported' => true],
            'bulk' => ['supported' => false, 'maxOperations' => 0, 'maxPayloadSize' => 0],
            'filter' => ['supported' => true, 'maxResults' => self::MAX_COUNT],
            'changePassword' => ['supported' => false],
            'sort' => ['supported' => false],
            'etag' => ['supported' => false],
            'authenticationSchemes' => [['type' => 'oauthbearertoken', 'name' => 'Bearer token', 'description' => 'The connection token as Authorization: Bearer', 'primary' => true]],
            'meta' => ['resourceType' => 'ServiceProviderConfig', 'location' => $this->location($connection) . '/ServiceProviderConfig'],
        ]);
    }
}
