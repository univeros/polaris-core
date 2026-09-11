<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use DateTimeImmutable;
use Polaris\Admin\Principal\IpAllowlist;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Sentinel\Model\IpRule;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function is_string;

/**
 * The instance's allow and block rules (`polaris_sentinel_ip_rule`); an allow rule clears an address
 * of every other signal, a block rule refuses it. Loaded once per request.
 */
final class IpRules
{
    /** @var list<IpRule>|null */
    private ?array $rules = null;

    public function __construct(private readonly DatabaseAdapter $database, private readonly ClockInterface $clock)
    {
    }

    /**
     * The first rule matching the address, in creation order; null when none.
     */
    public function match(string $ip): ?IpRule
    {
        foreach ($this->all() as $rule) {
            if (IpAllowlist::allows([$rule->cidr], $ip)) {
                return $rule;
            }
        }

        return null;
    }

    /**
     * @return list<IpRule>
     */
    public function all(): array
    {
        if ($this->rules === null) {
            $this->rules = [];
            foreach ($this->database->findMany(Schema::IP_RULES, [], ['id' => 'asc']) as $row) {
                $this->rules[] = self::hydrate($row);
            }
        }

        return $this->rules;
    }

    public function add(string $cidr, string $action, ?string $note, ?string $createdBy): IpRule
    {
        $rule = new IpRule();
        $rule->id = Uuid::v7()->toRfc4122();
        $rule->cidr = $cidr;
        $rule->action = $action;
        $rule->note = $note;
        $rule->createdBy = $createdBy;
        $rule->createdAt = $this->clock->now();
        $this->database->insert(Schema::IP_RULES, ['id' => $rule->id, 'cidr' => $cidr, 'action' => $action, 'note' => $note, 'created_by' => $createdBy, 'created_at' => $rule->createdAt]);
        $this->rules = null;

        return $rule;
    }

    public function remove(string $id): bool
    {
        $this->rules = null;

        return $this->database->delete(Schema::IP_RULES, ['id' => $id]) > 0;
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): IpRule
    {
        $rule = new IpRule();
        $rule->id = (string) $row['id'];
        $rule->cidr = (string) $row['cidr'];
        $rule->action = (string) $row['action'];
        $rule->note = is_string($row['note'] ?? null) && $row['note'] !== '' ? $row['note'] : null;
        $rule->createdBy = is_string($row['created_by'] ?? null) && $row['created_by'] !== '' ? $row['created_by'] : null;
        $created = $row['created_at'];
        $rule->createdAt = $created instanceof DateTimeImmutable ? $created : new DateTimeImmutable((string) $created);

        return $rule;
    }
}
