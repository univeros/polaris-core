<?php

declare(strict_types=1);

namespace Polaris\Admin\Http;

use DateTimeImmutable;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Principals;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function sprintf;

/**
 * What every admin endpoint shares: the principal the middleware attached, the role and scope check
 * that answers the `admin/*` problem documents, and the common problems.
 */
trait AdminRoute
{
    /**
     * The principal when it may perform `$capability` on the instance (`$organizationId` null) or on
     * the organization; otherwise the problem to answer.
     */
    protected function authorize(Input $input, Capability $capability, ?string $organizationId = null): Principal|Result
    {
        if ($input->attribute(Principals::IMPERSONATED) === true) {
            return $this->problem(403, 'admin/impersonation_denied', 'Impersonation denied', 'An impersonation token cannot call the admin routes.');
        }
        $principal = $input->attribute(Principals::ATTRIBUTE);
        if (!$principal instanceof Principal) {
            return $this->problem(401, 'admin/unauthorized', 'Unauthorized', 'An admin user or an API key is required.');
        }
        if (!$principal->allows($capability)) {
            return $this->problem(403, 'admin/forbidden', 'Forbidden', sprintf('The %s role does not allow this action.', $principal->role->value));
        }
        if (!$principal->covers($organizationId)) {
            return $this->problem(403, 'admin/forbidden', 'Forbidden', 'This action is outside the scope of your admin role.');
        }

        return $principal;
    }

    protected function missing(string $detail): Result
    {
        return $this->problem(404, 'admin/not_found', 'Not found', $detail);
    }

    protected function conflict(string $detail): Result
    {
        return $this->problem(409, 'admin/conflict', 'Conflict', $detail);
    }

    /**
     * @param list<string> $errors
     */
    protected function invalid(string $detail, array $errors = []): Result
    {
        return $this->problem(422, 'admin/invalid_input', 'Invalid input', $detail, $errors === [] ? [] : ['errors' => $errors]);
    }

    /**
     * @return DateTimeImmutable|null|false false when given and not a datetime
     */
    protected static function datetime(mixed $value): DateTimeImmutable|null|false
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (!is_string($value)) {
            return false;
        }
        try {
            return new DateTimeImmutable($value);
        } catch (\Exception) {
            return false;
        }
    }

    protected static function positiveInt(mixed $value, int $default): int|false
    {
        if ($value === null || $value === '') {
            return $default;
        }

        return is_numeric($value) && (int) $value >= 1 ? (int) $value : false;
    }

    protected static function text(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
