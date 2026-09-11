<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Http\Admin;

use Override;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sentinel\Decision;
use Polaris\Sentinel\Decisions;

use function in_array;
use function strtolower;

/**
 * `GET /admin/sentinel/decisions`: the decisions where a signal spoke, newest first.
 */
final class ListDecisionsEndpoint extends SentinelAdminEndpoint
{
    public function __construct(private readonly Decisions $decisions)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Read);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $action = self::text($input->get('action'));
        if ($action !== null && !in_array($action, [Decision::ALLOW, Decision::CHALLENGE, Decision::BLOCK], true)) {
            return $this->invalid('action must be allow, challenge or block.');
        }
        $limit = self::positiveInt($input->get('limit'), Decisions::DEFAULT_LIMIT);
        if ($limit === false) {
            return $this->invalid('limit must be a positive integer.');
        }
        $email = self::text($input->get('email'));

        return $this->respond(200, $this->decisions->list(
            $email === null ? null : strtolower($email),
            self::text($input->get('ip')),
            $action,
            self::text($input->get('cursor')),
            $limit,
        ));
    }
}
