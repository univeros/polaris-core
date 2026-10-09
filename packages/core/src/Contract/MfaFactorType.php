<?php

declare(strict_types=1);

namespace Polaris\Contract;

use Polaris\Exception\InvalidOtpException;
use Polaris\Mfa\ChallengePurpose;
use Polaris\Model\MfaFactor;
use SensitiveParameter;

/**
 * An MFA factor type a plugin adds to core's gate (`polaris/passkey` adds `passkey`). Core owns the
 * factor row (`auth_mfa_factors`: listed, relabelled, defaulted and removed by its own routes, confirmed
 * through {@see \Polaris\Mfa\MfaConfirmation}), the `login_mfa` ticket and the verify routes
 * (`/auth/mfa/verify`, `/auth/mfa/step-up`); the type owns the verification of what the client sends as
 * the `code`. Registered by a plugin implementing {@see MfaFactorTypeProvider}; core's own types
 * (`totp`, `sms`, `email`) cannot be replaced.
 */
interface MfaFactorType
{
    /**
     * The `type` value of the factor rows this verifies.
     */
    public function type(): string;

    /**
     * Verifies `$code` for a confirmed factor of this type under the purpose; returns when it clears.
     *
     * @throws InvalidOtpException the code does not verify (answered as a wrong code, never more)
     */
    public function verify(MfaFactor $factor, #[SensitiveParameter] string $code, ChallengePurpose $purpose): void;
}
