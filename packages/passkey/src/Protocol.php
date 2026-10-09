<?php

declare(strict_types=1);

namespace Polaris\Passkey;

use Polaris\Passkey\Model\Passkey;

/**
 * WebAuthn behind one interface: the options of each ceremony as the browser takes them
 * (`PublicKeyCredential*OptionsJSON`) and the verification of what it answers. {@see WebauthnProtocol}
 * is `web-auth/webauthn-lib`.
 */
interface Protocol
{
    /**
     * @param list<string> $excludeCredentialIds base64url
     * @return array<string, mixed>
     */
    public function creationOptions(string $challenge, string $userId, string $userName, string $displayName, array $excludeCredentialIds): array;

    /**
     * @param list<string> $allowCredentialIds base64url; none for a discoverable sign-in
     * @return array<string, mixed>
     */
    public function requestOptions(string $challenge, array $allowCredentialIds): array;

    /**
     * @param array<string, mixed> $options the creation options the challenge was issued with
     * @throws PasskeyException the attestation does not verify
     */
    public function attest(array $options, string $credentialJson): Attested;

    /**
     * @param array<string, mixed> $options the request options the challenge was issued with
     * @throws PasskeyException the assertion does not verify for the passkey
     */
    public function assert(array $options, string $credentialJson, Passkey $passkey, string $userHandle): Asserted;
}
