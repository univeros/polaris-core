<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Organizations;

use Override;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Organizations;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Model\Organization;

use function in_array;

/**
 * `GET /admin/organizations`: every organization, oldest first, filtered by `status`, paginated by `cursor`.
 */
final class ListOrganizationsEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Organizations $organizations)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Read);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $status = self::text($input->get('status'));
        if ($status !== null && !in_array($status, [Organization::STATUS_ACTIVE, Organization::STATUS_SUSPENDED], true)) {
            return $this->invalid('status must be active or suspended.');
        }
        $limit = self::positiveInt($input->get('limit'), Organizations::DEFAULT_LIMIT);
        if ($limit === false) {
            return $this->invalid('limit must be a positive integer.');
        }

        return $this->respond(200, $this->organizations->list($status, self::text($input->get('cursor')), $limit));
    }
}
