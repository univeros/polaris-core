<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use SensitiveParameter;

use function strtolower;
use function trim;

/**
 * What the engine judges: which action, who (email, IP, user agent, device cookie) and what the request
 * carried that a signal may check (a captcha token, the password for the breach lookup; neither is stored).
 */
final readonly class Attempt
{
    public const string SIGN_UP = 'sign_up';
    public const string SIGN_IN = 'sign_in';
    public const string PASSWORD_RESET = 'password_reset';
    public const string VERIFICATION_SEND = 'verification_send';
    public const string OTP_SEND = 'otp_send';

    public ?string $email;

    public function __construct(
        public string $kind,
        ?string $email = null,
        public ?string $ip = null,
        public ?string $userAgent = null,
        public ?string $deviceId = null,
        public ?string $captchaToken = null,
        #[SensitiveParameter] public ?string $password = null,
    ) {
        $email = $email === null ? null : strtolower(trim($email));
        $this->email = $email === '' ? null : $email;
    }
}
