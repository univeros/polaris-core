<?php

declare(strict_types=1);

namespace Polaris\Passkey\Factor;

use Override;
use Polaris\Contract\MfaFactorType;
use Polaris\Exception\InvalidOtpException;
use Polaris\Mfa\ChallengePurpose;
use Polaris\Model\MfaFactor;
use Polaris\Passkey\PasskeyException;
use Polaris\Passkey\PasskeyService;

/**
 * The `passkey` factor type for core's gate and step-up: the `code` is the assertion the browser
 * answered to `POST /passkey/authenticate/options`, verified for the passkey behind the factor.
 */
final class PasskeyFactorType implements MfaFactorType
{
    public const string TYPE = 'passkey';

    public function __construct(private readonly PasskeyService $service)
    {
    }

    #[Override]
    public function type(): string
    {
        return self::TYPE;
    }

    #[Override]
    public function verify(MfaFactor $factor, string $code, ChallengePurpose $purpose): void
    {
        try {
            $this->service->verifyFactor($factor, $code);
        } catch (PasskeyException) {
            // Why it failed stays here: core answers every refused second factor the same way.
            throw new InvalidOtpException('The verification code is invalid.');
        }
    }
}
