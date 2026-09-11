<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Keys;

use Override;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Keys;
use Polaris\Admin\Model\AdminKey;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_map;

/**
 * `GET /admin/keys`: every API key, never the secrets.
 */
final class ListKeysEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Keys $keys)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Own);
        if (!$principal instanceof Principal) {
            return $principal;
        }

        return $this->respond(200, ['data' => array_map(static fn(AdminKey $key): array => $key->toArray(), $this->keys->all())]);
    }
}
