<?php

declare(strict_types=1);

namespace Polaris\Audit\Http;

use Override;
use Polaris\Audit\Catalog;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /audit/types`: the catalog, name and description, for a signed-in user.
 */
final class TypesEndpoint extends Endpoint
{
    public function __construct(private readonly Catalog $catalog)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        if ($this->token($input) === null) {
            return $this->unauthorized();
        }
        $types = [];
        foreach ($this->catalog->all() as $name => $description) {
            $types[] = ['name' => $name, 'description' => $description];
        }

        return $this->respond(200, ['data' => $types]);
    }
}
