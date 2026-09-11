<?php

declare(strict_types=1);

namespace Polaris\Audit\Http;

use DateTimeImmutable;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_filter;
use function array_map;
use function array_values;
use function explode;
use function is_numeric;
use function is_string;
use function trim;

/**
 * What the audit routes share: the query parameters (`names`, `from`, `to`, `cursor`, `limit`) parsed
 * into an {@see AuditQuery}, or a 422 problem document.
 */
abstract class AuditEndpoint extends Endpoint
{
    /**
     * @return AuditQuery|Result the query, or the problem to answer
     */
    protected function query(Input $input, ?string $principalId = null, ?string $organizationId = null): AuditQuery|Result
    {
        $names = $input->get('names');
        $from = self::datetime($input->get('from'));
        $to = self::datetime($input->get('to'));
        $limit = $input->get('limit');
        if (($from === false) || ($to === false)) {
            return $this->problem(422, 'audit/invalid_query', 'Invalid query', 'from and to must be ISO-8601 datetimes.');
        }
        if ($limit !== null && (!is_numeric($limit) || (int) $limit < 1)) {
            return $this->problem(422, 'audit/invalid_query', 'Invalid query', 'limit must be a positive integer.');
        }
        $cursor = $input->get('cursor');

        return new AuditQuery(
            names: is_string($names) && $names !== '' ? array_values(array_filter(array_map(trim(...), explode(',', $names)), static fn(string $name): bool => $name !== '')) : [],
            principalId: $principalId,
            organizationId: $organizationId,
            from: $from,
            to: $to,
            cursor: is_string($cursor) && $cursor !== '' ? $cursor : null,
            limit: $limit === null ? AuditQuery::DEFAULT_LIMIT : (int) $limit,
        );
    }

    /**
     * @return DateTimeImmutable|null|false false when given and invalid
     */
    private static function datetime(mixed $value): DateTimeImmutable|null|false
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
}
