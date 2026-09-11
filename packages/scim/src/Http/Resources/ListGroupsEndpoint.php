<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Resources;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\Filter;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\ScimError;

use function is_string;

/**
 * `GET /scim/v2/{connectionId}/Groups?filter=&startIndex=&count=`.
 */
final class ListGroupsEndpoint extends GroupEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        $connection = $this->connection($input);
        if (!$connection instanceof Connection) {
            return $connection;
        }
        try {
            $filter = Filter::parse(is_string($input->get('filter')) ? $input->get('filter') : null);
        } catch (ScimError $error) {
            return $this->error($error, $connection, $input);
        }

        return $this->page($this->groups->list($connection, $filter, $this->startIndex($input), $this->count($input), $this->location($connection)), $this->startIndex($input));
    }
}
