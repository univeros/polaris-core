<?php

declare(strict_types=1);

namespace Polaris\Scim\Http;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\AuditNames;
use Polaris\Scim\Connections;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\ScimAudit;
use Polaris\Scim\ScimError;
use Polaris\Scim\Sp;

use function is_numeric;
use function max;
use function min;

/**
 * What every `/scim/v2/{connectionId}` route shares: the connection the middleware resolved (it must be
 * the path's and active), SCIM documents and SCIM errors (`application/scim+json`, RFC 7644 §3.12) that
 * also carry `error` and `message`, pagination, the base location of the resources.
 */
abstract class ScimEndpoint extends Endpoint
{
    public const string CONTENT_TYPE = 'application/scim+json';
    public const string LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
    public const string ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
    public const int MAX_COUNT = 200;

    public function __construct(protected readonly Connections $connections, protected readonly ScimAudit $audit, protected readonly Sp $sp)
    {
    }

    /**
     * The connection when the bearer is the path's active connection; the 401 otherwise.
     */
    protected function connection(Input $input): Connection|Result
    {
        $connection = $input->attribute(ScimMiddleware::ATTRIBUTE);
        if (!$connection instanceof Connection || $connection->id !== (string) $input->get('connectionId')) {
            return $this->error(new ScimError(401, 'A valid connection token is required.'));
        }
        $this->connections->touch($connection);

        return $connection;
    }

    /**
     * @param array<string, mixed> $document
     */
    protected function scim(int $status, array $document): Result
    {
        return new Result($status, $document, ['Content-Type' => self::CONTENT_TYPE]);
    }

    /**
     * @param array{total: int, resources: list<array<string, mixed>>} $page
     */
    protected function page(array $page, int $startIndex): Result
    {
        return $this->scim(200, [
            'schemas' => [self::LIST_SCHEMA],
            'totalResults' => $page['total'],
            'startIndex' => $startIndex,
            'itemsPerPage' => count($page['resources']),
            'Resources' => $page['resources'],
        ]);
    }

    protected function error(ScimError $error, ?Connection $connection = null, ?Input $input = null): Result
    {
        if ($connection !== null && $input !== null) {
            $this->audit->record(AuditNames::REQUEST_REJECTED, $connection, null, ['status' => $error->status, 'reason' => $error->detail], $this->client($input));
        }
        $document = ['schemas' => [self::ERROR_SCHEMA], 'status' => (string) $error->status, 'detail' => $error->detail, 'error' => 'scim_' . ($error->scimType ?? 'error'), 'message' => $error->detail];
        if ($error->scimType !== null) {
            $document['scimType'] = $error->scimType;
        }

        return new Result($error->status, $document, ['Content-Type' => self::CONTENT_TYPE]);
    }

    protected function startIndex(Input $input): int
    {
        $value = $input->get('startIndex');

        return is_numeric($value) ? max(1, (int) $value) : 1;
    }

    protected function count(Input $input): int
    {
        $value = $input->get('count');

        return is_numeric($value) ? max(0, min(self::MAX_COUNT, (int) $value)) : 100;
    }

    protected function location(Connection $connection): string
    {
        return $this->sp->location($connection->id);
    }

    /**
     * @return array<string, mixed>
     */
    protected function body(Input $input): array
    {
        $body = [];
        foreach ($input->all() as $key => $value) {
            if ($key !== 'connectionId' && $key !== 'id') {
                $body[(string) $key] = $value;
            }
        }

        return $body;
    }
}
