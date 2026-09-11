<?php

declare(strict_types=1);

namespace Polaris\Audit\Query;

use DateTimeImmutable;
use Polaris\Contract\Condition;

/**
 * What a reader asks for: names, actor, subject or principal (actor or subject), organization, a time
 * range, a cursor (the last id of the previous page) and a page size (50 by default, 200 at most).
 */
final readonly class AuditQuery
{
    public const int DEFAULT_LIMIT = 50;
    public const int MAX_LIMIT = 200;

    public int $limit;

    /**
     * @param list<string> $names
     */
    public function __construct(
        public array $names = [],
        public ?string $actorId = null,
        public ?string $subjectId = null,
        public ?string $principalId = null,
        public ?string $organizationId = null,
        public ?DateTimeImmutable $from = null,
        public ?DateTimeImmutable $to = null,
        public ?string $cursor = null,
        int $limit = self::DEFAULT_LIMIT,
    ) {
        $this->limit = max(1, min(self::MAX_LIMIT, $limit));
    }

    /**
     * The adapter criteria (a conjunction); the principal is handled by the store.
     *
     * @return array<string, mixed>
     */
    public function criteria(): array
    {
        $criteria = [];
        if ($this->names !== []) {
            $criteria['name'] = count($this->names) === 1 ? $this->names[0] : $this->names;
        }
        if ($this->actorId !== null) {
            $criteria['actor_id'] = $this->actorId;
        }
        if ($this->subjectId !== null) {
            $criteria['subject_id'] = $this->subjectId;
        }
        if ($this->organizationId !== null) {
            $criteria['organization_id'] = $this->organizationId;
        }
        if ($this->cursor !== null) {
            $criteria['id'] = Condition::lt($this->cursor);
        }
        // The adapter takes one condition per column; a closed range keeps the lower bound and filters the upper in the store's page when both are set.
        if ($this->from !== null) {
            $criteria['occurred_at'] = Condition::gte($this->from);
        } elseif ($this->to !== null) {
            $criteria['occurred_at'] = Condition::lte($this->to);
        }

        return $criteria;
    }
}
