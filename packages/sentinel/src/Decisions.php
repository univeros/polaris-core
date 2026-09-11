<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use DateTimeImmutable;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Sentinel\Model\DecisionRecord;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function array_slice;
use function count;
use function is_string;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * The decisions where a signal spoke (`polaris_sentinel_decision`), newest first for the operators.
 */
final class Decisions
{
    public const int DEFAULT_LIMIT = 50;
    public const int MAX_LIMIT = 200;

    public function __construct(private readonly DatabaseAdapter $database, private readonly ClockInterface $clock)
    {
    }

    public function record(Attempt $attempt, Decision $decision): DecisionRecord
    {
        $record = new DecisionRecord();
        $record->id = Uuid::v7()->toRfc4122();
        $record->kind = $attempt->kind;
        $record->email = $attempt->email;
        $record->ip = $attempt->ip;
        $record->score = $decision->score;
        $record->action = $decision->action;
        $record->enforced = $decision->enforced;
        $record->signals = json_encode($decision->signals(), JSON_THROW_ON_ERROR);
        $record->reasons = json_encode($decision->reasons(), JSON_THROW_ON_ERROR);
        $record->createdAt = $this->clock->now();
        $this->database->insert(Schema::DECISIONS, [
            'id' => $record->id,
            'kind' => $record->kind,
            'email' => $record->email,
            'ip' => $record->ip,
            'score' => $record->score,
            'action' => $record->action,
            'enforced' => $record->enforced,
            'signals' => $record->signals,
            'reasons' => $record->reasons,
            'created_at' => $record->createdAt,
        ]);

        return $record;
    }

    /**
     * @return array{data: list<array<string, mixed>>, next_cursor: string|null}
     */
    public function list(?string $email = null, ?string $ip = null, ?string $action = null, ?string $cursor = null, int $limit = self::DEFAULT_LIMIT): array
    {
        $limit = max(1, min(self::MAX_LIMIT, $limit));
        $criteria = [];
        if ($email !== null) {
            $criteria['email'] = $email;
        }
        if ($ip !== null) {
            $criteria['ip'] = $ip;
        }
        if ($action !== null) {
            $criteria['action'] = $action;
        }
        if ($cursor !== null) {
            $criteria['id'] = Condition::lt($cursor);
        }
        $rows = $this->database->findMany(Schema::DECISIONS, $criteria, ['id' => 'desc'], $limit + 1);
        $data = [];
        foreach (array_slice($rows, 0, $limit) as $row) {
            $data[] = self::hydrate($row)->toArray();
        }

        return ['data' => $data, 'next_cursor' => count($rows) > $limit && $data !== [] ? $data[count($data) - 1]['id'] : null];
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): DecisionRecord
    {
        $record = new DecisionRecord();
        $record->id = (string) $row['id'];
        $record->kind = (string) $row['kind'];
        $record->email = is_string($row['email'] ?? null) && $row['email'] !== '' ? $row['email'] : null;
        $record->ip = is_string($row['ip'] ?? null) && $row['ip'] !== '' ? $row['ip'] : null;
        $record->score = (int) $row['score'];
        $record->action = (string) $row['action'];
        $record->enforced = (bool) $row['enforced'];
        $record->signals = is_string($row['signals']) ? $row['signals'] : json_encode($row['signals'], JSON_THROW_ON_ERROR);
        $record->reasons = is_string($row['reasons']) ? $row['reasons'] : json_encode($row['reasons'], JSON_THROW_ON_ERROR);
        $created = $row['created_at'];
        $record->createdAt = $created instanceof DateTimeImmutable ? $created : new DateTimeImmutable((string) $created);

        return $record;
    }
}
