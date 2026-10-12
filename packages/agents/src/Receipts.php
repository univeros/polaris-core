<?php

declare(strict_types=1);

namespace Polaris\Agents;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Grant;
use Polaris\Agents\Model\Receipt;
use Polaris\Config\Secrets;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\TokenConfigurationInterface;
use Polaris\OAuth\Jwt;
use Polaris\OAuth\OAuthException;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;
use Throwable;

use function array_is_list;
use function hash;
use function hash_equals;
use function is_array;
use function is_string;
use function json_encode;
use function ksort;
use function max;
use function min;
use function str_starts_with;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * The receipt chain (`polaris_agent_receipt`): one receipt per execution, appended in the execution's
 * transaction with `seq` = the previous plus one, `prev_hash` the previous receipt's hash, `hash` the
 * SHA-256 of the canonical JSON of its fields, and `signature` a compact JWS (`typ: receipt+jwt`) over
 * the hash signed with core's key and `kid`, so `/auth/.well-known/jwks.json` verifies it. Revoking an
 * agent appends a final `sealed` receipt; nothing is chained after it.
 */
final class Receipts
{
    public const string TYP = 'receipt+jwt';
    public const int MAX_PAGE = 200;

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly TokenConfigurationInterface $config,
        private readonly Secrets $secrets,
        private readonly Jwt $jwt,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * The next receipt of the agent's chain; the caller holds the transaction. The chain's unique
     * `(agent_id, seq)` makes a concurrent append fail (`conflict`) rather than fork.
     *
     * @throws AgentException `sealed` when the chain was sealed, `conflict` when another receipt took the seq
     */
    public function append(Agent $agent, ?Grant $grant, ?string $capability, string $inputHash, string $outcome, ?int $budgetBefore, ?int $budgetAfter): Receipt
    {
        $previous = $this->last($agent);
        if ($previous !== null && $previous->outcome === Receipt::OUTCOME_SEALED) {
            throw new AgentException(AgentException::SEALED, 'The agent\'s receipt chain is sealed.');
        }
        $receipt = new Receipt();
        $receipt->id = Uuid::v7()->toRfc4122();
        $receipt->agentId = $agent->id;
        $receipt->seq = $previous === null ? 1 : $previous->seq + 1;
        $receipt->grantId = $grant?->id;
        $receipt->capability = $capability;
        $receipt->inputHash = $inputHash;
        $receipt->outcome = $outcome;
        $receipt->budgetBefore = $budgetBefore;
        $receipt->budgetAfter = $budgetAfter;
        $receipt->prevHash = $previous?->hash;
        $receipt->createdAt = $this->clock->now();
        $receipt->hash = self::hashOf($receipt);
        $receipt->signature = $this->sign($receipt);
        try {
            $this->database->insert(Schema::RECEIPTS, $this->row($receipt));
        } catch (Throwable $exception) {
            if (!self::isIntegrityViolation($exception)) {
                throw $exception;
            }
            throw new AgentException(AgentException::CONFLICT, 'Another receipt was appended to the chain meanwhile; retry.');
        }

        return $receipt;
    }

    /**
     * The final receipt of a revoked agent.
     */
    public function seal(Agent $agent): Receipt
    {
        return $this->append($agent, null, null, self::inputHash([]), Receipt::OUTCOME_SEALED, null, null);
    }

    /**
     * Recomputes the hash, verifies the signature with core's public key(s) and checks the link to the
     * previous receipt.
     *
     * @return array{valid: bool, checks: array{hash: bool, signature: bool, chain: bool}}
     */
    public function verify(Receipt $receipt): array
    {
        $hash = hash_equals(self::hashOf($receipt), $receipt->hash);
        $signature = false;
        try {
            $claims = $this->jwt->verify($receipt->signature, self::TYP)['claims'];
            // The signature vouches for the hash of the fields as they are now, not for the stored hash.
            $signature = is_string($claims['receipt_hash'] ?? null) && hash_equals($claims['receipt_hash'], self::hashOf($receipt))
                && ($claims['receipt_id'] ?? null) === $receipt->id && ($claims['agent_id'] ?? null) === $receipt->agentId && ($claims['seq'] ?? null) === $receipt->seq;
        } catch (OAuthException) {
            $signature = false;
        }
        if ($receipt->seq === 1) {
            $chain = $receipt->prevHash === null;
        } else {
            $previous = $this->at($receipt->agentId, $receipt->seq - 1);
            // Against the previous receipt's fields as they are now, so a tampered predecessor breaks the link too.
            $chain = $previous !== null && $receipt->prevHash !== null && hash_equals(self::hashOf($previous), $receipt->prevHash);
        }

        return ['valid' => $hash && $signature && $chain, 'checks' => ['hash' => $hash, 'signature' => $signature, 'chain' => $chain]];
    }

    public function find(string $id): ?Receipt
    {
        $row = $this->database->findOne(Schema::RECEIPTS, ['id' => $id]);

        return $row === null ? null : self::hydrate($row);
    }

    public function last(Agent $agent): ?Receipt
    {
        $rows = $this->database->findMany(Schema::RECEIPTS, ['agent_id' => $agent->id], ['seq' => 'desc'], 1);

        return $rows === [] ? null : self::hydrate($rows[0]);
    }

    /**
     * The chain from `$after` on, oldest first, at most `$limit` receipts.
     *
     * @return list<Receipt>
     */
    public function forAgent(Agent $agent, int $after = 0, int $limit = 100): array
    {
        $limit = max(1, min(self::MAX_PAGE, $limit));
        $receipts = [];
        foreach ($this->database->findMany(Schema::RECEIPTS, ['agent_id' => $agent->id], ['seq' => 'asc'], $limit, max(0, $after)) as $row) {
            $receipts[] = self::hydrate($row);
        }

        return $receipts;
    }

    public function deleteForAgent(Agent $agent): void
    {
        $this->database->delete(Schema::RECEIPTS, ['agent_id' => $agent->id]);
    }

    /**
     * The SHA-256 (hex) of the canonical JSON of the arguments: what a receipt keeps of the input.
     *
     * @param array<string, mixed> $arguments
     */
    public static function inputHash(array $arguments): string
    {
        return hash('sha256', self::canonical($arguments));
    }

    /**
     * SHA-256 (hex) over the canonical JSON of the receipt's fields.
     */
    public static function hashOf(Receipt $receipt): string
    {
        return hash('sha256', self::canonical($receipt->hashed()));
    }

    /**
     * Canonical JSON: keys sorted at every level, slashes unescaped, no whitespace.
     *
     * @param array<mixed> $value
     */
    public static function canonical(array $value): string
    {
        return json_encode(self::sorted($value), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * @param array<mixed> $value
     * @return array<mixed>
     */
    private static function sorted(array $value): array
    {
        foreach ($value as $key => $item) {
            if (is_array($item)) {
                $value[$key] = self::sorted($item);
            }
        }
        if (!array_is_list($value)) {
            ksort($value);
        }

        return $value;
    }

    /**
     * Whether a driver exception is an integrity constraint violation (SQLSTATE class 23, the unique
     * index on the chain), anywhere in its chain of causes.
     */
    private static function isIntegrityViolation(Throwable $exception): bool
    {
        for ($cause = $exception; $cause !== null; $cause = $cause->getPrevious()) {
            if (str_starts_with((string) $cause->getCode(), '23')) {
                return true;
            }
        }

        return false;
    }

    private function sign(Receipt $receipt): string
    {
        $configuration = Configuration::forAsymmetricSigner($this->config->getSigner(), InMemory::plainText((string) $this->config->getPrivateKey()), InMemory::plainText($this->config->getPublicKey()));
        $builder = $configuration->builder()
            ->issuedBy($this->config->getIssuer())
            ->issuedAt($receipt->createdAt)
            ->withHeader('kid', $this->secrets->jwtKid)
            ->withHeader('typ', self::TYP)
            ->withClaim('receipt_hash', $receipt->hash)
            ->withClaim('receipt_id', $receipt->id)
            ->withClaim('agent_id', $receipt->agentId)
            ->withClaim('seq', $receipt->seq);

        return $builder->getToken($configuration->signer(), $configuration->signingKey())->toString();
    }

    private function at(string $agentId, int $seq): ?Receipt
    {
        $row = $this->database->findOne(Schema::RECEIPTS, ['agent_id' => $agentId, 'seq' => $seq]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * @return array<string, mixed>
     */
    private function row(Receipt $receipt): array
    {
        return [
            'id' => $receipt->id,
            'agent_id' => $receipt->agentId,
            'seq' => $receipt->seq,
            'grant_id' => $receipt->grantId,
            'capability' => $receipt->capability,
            'input_hash' => $receipt->inputHash,
            'outcome' => $receipt->outcome,
            'budget_before' => $receipt->budgetBefore,
            'budget_after' => $receipt->budgetAfter,
            'prev_hash' => $receipt->prevHash,
            'hash' => $receipt->hash,
            'signature' => $receipt->signature,
            'created_at' => $receipt->createdAt,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Receipt
    {
        $receipt = new Receipt();
        $receipt->id = (string) $row['id'];
        $receipt->agentId = (string) $row['agent_id'];
        $receipt->seq = (int) $row['seq'];
        $receipt->grantId = Rows::nullable($row['grant_id'] ?? null);
        $receipt->capability = Rows::nullable($row['capability'] ?? null);
        $receipt->inputHash = (string) $row['input_hash'];
        $receipt->outcome = (string) $row['outcome'];
        $receipt->budgetBefore = Rows::int($row['budget_before'] ?? null);
        $receipt->budgetAfter = Rows::int($row['budget_after'] ?? null);
        $receipt->prevHash = Rows::nullable($row['prev_hash'] ?? null);
        $receipt->hash = (string) $row['hash'];
        $receipt->signature = (string) $row['signature'];
        $receipt->createdAt = Rows::datetime($row['created_at']) ?? new DateTimeImmutable();

        return $receipt;
    }
}
