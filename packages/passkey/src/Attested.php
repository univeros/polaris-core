<?php

declare(strict_types=1);

namespace Polaris\Passkey;

/**
 * What a verified registration yields: the credential as the authenticator presented it (base64url),
 * its public key (COSE, base64url), the counter, the authenticator's aaguid, the transports and flags.
 */
final readonly class Attested
{
    /**
     * @param list<string> $transports
     */
    public function __construct(
        public string $credentialId,
        public string $publicKey,
        public int $counter,
        public string $aaguid,
        public array $transports,
        public bool $backupEligible,
        public bool $backedUp,
        public bool $userVerified,
    ) {
    }
}
