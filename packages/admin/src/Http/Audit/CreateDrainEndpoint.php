<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Audit;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Organizations;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Audit\Drain\Drains;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_values;
use function filter_var;
use function is_array;
use function is_string;
use function str_starts_with;
use function strlen;

use const FILTER_VALIDATE_URL;

/**
 * `POST /admin/organizations/{id}/drains`: a signed webhook drain for the organization's events.
 */
final class CreateDrainEndpoint extends AdminEndpoint
{
    private const int MIN_SECRET_LENGTH = 16;

    public function __construct(private readonly Organizations $organizations, private readonly Drains $drains, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $organizationId = (string) $input->get('id');
        $principal = $this->authorize($input, Capability::Own, $organizationId);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $endpoint = $input->get('endpoint');
        if (!is_string($endpoint) || filter_var($endpoint, FILTER_VALIDATE_URL) === false || !str_starts_with($endpoint, 'https://')) {
            return $this->invalid('endpoint must be an https URL.');
        }
        $secret = $input->get('secret');
        if (!is_string($secret) || strlen($secret) < self::MIN_SECRET_LENGTH) {
            return $this->invalid('secret must be at least 16 characters.');
        }
        $filter = $input->get('filter', []);
        if (!is_array($filter)) {
            return $this->invalid('filter must be a list of event names or prefix.* patterns.');
        }
        foreach ($filter as $pattern) {
            if (!is_string($pattern) || $pattern === '') {
                return $this->invalid('filter must be a list of event names or prefix.* patterns.');
            }
        }
        if ($this->organizations->find($organizationId) === null) {
            return $this->missing('The organization does not exist.');
        }
        $drain = $this->drains->create($organizationId, $endpoint, $secret, array_values($filter), $principal->id);
        $this->audit->record(AdminAudit::DRAIN_CREATED, $principal, null, $organizationId, ['drain_id' => $drain->id, 'endpoint' => $endpoint], $this->client($input));

        return $this->respond(201, ['data' => $drain->toArray()]);
    }
}
