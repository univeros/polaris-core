<?php

declare(strict_types=1);

namespace Polaris\Agents;

use LogicException;

use function in_array;
use function is_array;
use function is_string;
use function preg_match;
use function rtrim;

/**
 * The plugin's configuration: where Polaris is mounted (the discovery document's endpoints derive from
 * it), the host's approval page, the auto-approval policy and the approval strength per risk tier,
 * the lifetimes, and what the discovery document says about the provider.
 */
final readonly class Settings
{
    public const string RISK_LOW = 'low';
    public const string RISK_MEDIUM = 'medium';
    public const string RISK_HIGH = 'high';
    public const array RISKS = [self::RISK_LOW, self::RISK_MEDIUM, self::RISK_HIGH];

    public const string STRENGTH_SESSION = 'session';
    public const string STRENGTH_STEP_UP = 'step_up';
    public const string STRENGTH_PASSKEY = 'passkey';
    public const array STRENGTHS = [self::STRENGTH_SESSION, self::STRENGTH_STEP_UP, self::STRENGTH_PASSKEY];

    public const array DEFAULT_AUTO_APPROVE = [self::RISK_LOW => ['count' => 100]];
    public const array DEFAULT_STRENGTHS = [self::RISK_LOW => self::STRENGTH_SESSION, self::RISK_MEDIUM => self::STRENGTH_SESSION, self::RISK_HIGH => self::STRENGTH_STEP_UP];

    public string $baseUrl;
    public ?string $approvalUrl;
    /** @var array<string, array<string, mixed>|true> risk => the default budget (`{count}` or `{amount, field}`), or true for none */
    public array $autoApprove;
    /** @var array<string, string> risk => strength */
    public array $strengths;

    /**
     * @param array<string, mixed> $autoApprove risk tiers approved without a person when the owner holds the permission, with the budget they get (`{count}` or `{amount, field}`, or true for none)
     * @param array<string, mixed> $strengths the approval strength each risk tier needs
     */
    public function __construct(
        string $baseUrl,
        ?string $approvalUrl = null,
        array $autoApprove = self::DEFAULT_AUTO_APPROVE,
        array $strengths = [],
        public int $approvalTtl = 600,
        public string $providerName = 'Polaris',
        public string $description = 'Polaris for PHP agent provider',
        public int $requestJwtMaxAge = 300,
    ) {
        if (preg_match('~^https?://[^/\s]+~', $baseUrl) !== 1) {
            throw new LogicException('baseUrl must be an absolute http(s) URL, where Polaris is mounted.');
        }
        if ($approvalUrl !== null && preg_match('~^https?://[^\s?]+$~', $approvalUrl) !== 1) {
            throw new LogicException('approvalUrl must be an absolute http(s) URL without a query.');
        }
        foreach ($autoApprove as $risk => $budget) {
            if (!in_array($risk, self::RISKS, true) || ($budget !== true && !is_array($budget))) {
                throw new LogicException('autoApprove maps a risk tier (low, medium, high) to a budget or true.');
            }
            if (is_array($budget)) {
                try {
                    Constraints::budget($budget);
                } catch (AgentException $exception) {
                    throw new LogicException('autoApprove: ' . $exception->detail);
                }
            }
        }
        $merged = self::DEFAULT_STRENGTHS;
        foreach ($strengths as $risk => $strength) {
            if (!in_array($risk, self::RISKS, true) || !is_string($strength) || !in_array($strength, self::STRENGTHS, true)) {
                throw new LogicException('strengths maps a risk tier (low, medium, high) to session, step_up or passkey.');
            }
            $merged[$risk] = $strength;
        }
        if ($approvalTtl < 1 || $requestJwtMaxAge < 1 || $requestJwtMaxAge > 300) {
            throw new LogicException('approvalTtl is at least one second; requestJwtMaxAge is between 1 and 300 seconds.');
        }
        if ($providerName === '') {
            throw new LogicException('providerName is required.');
        }
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->approvalUrl = $approvalUrl === null ? null : rtrim($approvalUrl, '/');
        /** @var array<string, array<string, mixed>|true> $autoApprove */
        $this->autoApprove = $autoApprove;
        $this->strengths = $merged;
    }

    /**
     * The absolute URL of one of the plugin's routes (`/agents/execute`).
     */
    public function url(string $path): string
    {
        return $this->baseUrl . $path;
    }

    public function strengthFor(string $risk): string
    {
        return $this->strengths[$risk] ?? self::STRENGTH_STEP_UP;
    }
}
