<?php

declare(strict_types=1);

namespace Polaris\Audit;

use DateTimeImmutable;
use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Query\Page;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Symfony\Component\Uid\Uuid;

use function array_filter;
use function array_slice;
use function array_values;
use function count;
use function hash;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function ksort;
use function usort;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * Reads and writes `polaris_audit_event` through the database adapter. Ids are UUID v7, so ordering
 * by id is ordering by time and a cursor is the last id seen. With the hash chain on, each row's
 * `hash` is SHA-256 over its canonical JSON plus the previous row's hash, computed inside one
 * transaction per write.
 */
final class Store
{
    public function __construct(private readonly DatabaseAdapter $database, private readonly bool $hashChain = false)
    {
    }

    public function write(AuditEvent $event): void
    {
        if ($event->id === '') {
            $event->id = Uuid::v7()->toRfc4122();
        }
        if (!$this->hashChain) {
            $this->database->insert(Schema::EVENTS, $this->row($event));

            return;
        }
        $this->database->transaction(function () use ($event): void {
            $event->prevHash = $this->lastHash();
            $event->hash = self::hashOf($event);
            $this->database->insert(Schema::EVENTS, $this->row($event));
        });
    }

    public function lastHash(): ?string
    {
        $rows = $this->database->findMany(Schema::EVENTS, [], ['id' => 'desc'], 1);
        $hash = $rows[0]['hash'] ?? null;

        return is_string($hash) && $hash !== '' ? $hash : null;
    }

    public static function hashOf(AuditEvent $event): string
    {
        $canonical = $event->toArray();
        $canonical['prev_hash'] = $event->prevHash;
        ksort($canonical);

        return hash('sha256', json_encode($canonical, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    /**
     * Newest first; a principal filter (actor or subject) is two reads merged, because the adapter's
     * criteria are conjunctions.
     */
    public function read(AuditQuery $query): Page
    {
        $criteria = $query->criteria();
        if ($query->principalId === null) {
            return $this->page($this->until($this->database->findMany(Schema::EVENTS, $criteria, ['id' => 'desc'], $query->limit + 1), $query), $query->limit);
        }
        $rows = [
            ...$this->database->findMany(Schema::EVENTS, ['actor_id' => $query->principalId, ...$criteria], ['id' => 'desc'], $query->limit + 1),
            ...$this->database->findMany(Schema::EVENTS, ['subject_id' => $query->principalId, ...$criteria], ['id' => 'desc'], $query->limit + 1),
        ];
        $unique = [];
        foreach ($rows as $row) {
            $unique[(string) $row['id']] = $row;
        }
        usort($unique, static fn(array $a, array $b): int => (string) $b['id'] <=> (string) $a['id']);

        return $this->page(array_slice($this->until($unique, $query), 0, $query->limit + 1), $query->limit);
    }

    /**
     * The upper bound of a closed range, applied here because the adapter takes one condition per column.
     *
     * @param list<array<string, mixed>> $rows
     * @return list<array<string, mixed>>
     */
    private function until(array $rows, AuditQuery $query): array
    {
        if ($query->from === null || $query->to === null) {
            return $rows;
        }

        return array_values(array_filter($rows, static fn(array $row): bool => self::datetime($row['occurred_at']) <= $query->to));
    }

    /**
     * Rows older than `$before` for one name, or every name when null.
     */
    public function deleteBefore(DateTimeImmutable $before, ?string $name = null): int
    {
        return $this->database->delete(Schema::EVENTS, ['occurred_at' => Condition::lt($before), ...($name === null ? [] : ['name' => $name])]);
    }

    /**
     * The newest event older than `$before` (its hash closes a pruned segment of the chain).
     */
    public function newestBefore(DateTimeImmutable $before, ?string $name = null): ?AuditEvent
    {
        $rows = $this->database->findMany(Schema::EVENTS, ['occurred_at' => Condition::lt($before), ...($name === null ? [] : ['name' => $name])], ['id' => 'desc'], 1);

        return $rows === [] ? null : $this->hydrate($rows[0]);
    }

    /**
     * Every event in chain order, in batches.
     *
     * @return iterable<AuditEvent>
     */
    public function walk(int $batch = 500): iterable
    {
        $after = null;
        while (true) {
            $rows = $this->database->findMany(Schema::EVENTS, $after === null ? [] : ['id' => Condition::gt($after)], ['id' => 'asc'], $batch);
            foreach ($rows as $row) {
                $event = $this->hydrate($row);
                $after = $event->id;
                yield $event;
            }
            if (count($rows) < $batch) {
                return;
            }
        }
    }

    public function count(): int
    {
        return $this->database->count(Schema::EVENTS, []);
    }

    /**
     * The `last_hash` of every pruning checkpoint: the hashes a chain may legitimately continue from.
     *
     * @return list<string>
     */
    public function checkpointHashes(): array
    {
        $hashes = [];
        foreach ($this->database->findMany(Schema::EVENTS, ['name' => Catalog::AUDIT_PRUNED]) as $row) {
            $hash = $this->hydrate($row)->data['last_hash'] ?? null;
            if (is_string($hash) && $hash !== '') {
                $hashes[] = $hash;
            }
        }

        return $hashes;
    }

    /**
     * @param array<string, mixed> $row
     */
    public function hydrate(array $row): AuditEvent
    {
        $event = new AuditEvent();
        $event->id = (string) $row['id'];
        $event->name = (string) $row['name'];
        $event->occurredAt = self::datetime($row['occurred_at']);
        $event->actorType = (string) $row['actor_type'];
        $event->actorId = self::nullable($row['actor_id'] ?? null);
        $event->subjectId = self::nullable($row['subject_id'] ?? null);
        $event->organizationId = self::nullable($row['organization_id'] ?? null);
        $event->sessionId = self::nullable($row['session_id'] ?? null);
        $event->ip = self::nullable($row['ip'] ?? null);
        $event->userAgent = self::nullable($row['user_agent'] ?? null);
        $data = $row['data'] ?? [];
        $decoded = is_string($data) ? json_decode($data, true) : $data;
        $event->data = is_array($decoded) ? $decoded : [];
        $event->requestId = self::nullable($row['request_id'] ?? null);
        $event->prevHash = self::nullable($row['prev_hash'] ?? null);
        $event->hash = self::nullable($row['hash'] ?? null);

        return $event;
    }

    /**
     * @param list<array<string, mixed>> $rows one more than the limit, to know whether a next page exists
     */
    private function page(array $rows, int $limit): Page
    {
        $events = [];
        foreach (array_slice($rows, 0, $limit) as $row) {
            $events[] = $this->hydrate($row);
        }

        return new Page($events, count($rows) > $limit && $events !== [] ? $events[count($events) - 1]->id : null);
    }

    /**
     * @return array<string, mixed>
     */
    private function row(AuditEvent $event): array
    {
        return [
            'id' => $event->id,
            'name' => $event->name,
            'occurred_at' => $event->occurredAt,
            'actor_type' => $event->actorType,
            'actor_id' => $event->actorId,
            'subject_id' => $event->subjectId,
            'organization_id' => $event->organizationId,
            'session_id' => $event->sessionId,
            'ip' => $event->ip,
            'user_agent' => $event->userAgent,
            'data' => json_encode($event->data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            'request_id' => $event->requestId,
            'prev_hash' => $event->prevHash,
            'hash' => $event->hash,
        ];
    }

    private static function datetime(mixed $value): DateTimeImmutable
    {
        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }

    private static function nullable(mixed $value): ?string
    {
        return $value === null || $value === '' ? null : (string) $value;
    }
}
