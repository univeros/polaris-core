<?php

declare(strict_types=1);

namespace Polaris\Tests\Support\Plugin;

use Override;
use Polaris\Contract\MfaFactorType;
use Polaris\Exception\InvalidOtpException;
use Polaris\Mfa\ChallengePurpose;
use Polaris\Model\MfaFactor;

/**
 * A factor type for the seam's tests: accepts `stamp:<factor id>` and records every verification.
 */
final class StampFactorType implements MfaFactorType
{
    /** @var list<array{string, string, ChallengePurpose}> */
    public array $verified = [];

    public function __construct(private readonly string $type = 'stamp')
    {
    }

    /**
     * @return list<array{string, string, ChallengePurpose}>
     */
    public function verifications(): array
    {
        return $this->verified;
    }

    #[Override]
    public function type(): string
    {
        return $this->type;
    }

    #[Override]
    public function verify(MfaFactor $factor, string $code, ChallengePurpose $purpose): void
    {
        $this->verified[] = [$factor->id, $code, $purpose];
        if ($code !== 'stamp:' . $factor->id) {
            throw new InvalidOtpException('The verification code is invalid.');
        }
    }
}
