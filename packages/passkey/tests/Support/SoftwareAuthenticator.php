<?php

declare(strict_types=1);

namespace Polaris\Passkey\Tests\Support;

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use OpenSSLAsymmetricKey;
use Polaris\Passkey\Base64Url;
use RuntimeException;

use function chr;
use function hash;
use function is_array;
use function json_encode;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function openssl_sign;
use function pack;
use function random_bytes;
use function str_pad;
use function str_repeat;
use function strlen;

use const JSON_THROW_ON_ERROR;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;
use const STR_PAD_LEFT;

/**
 * A platform authenticator in software: a P-256 key per credential, `none` attestation, user presence
 * and (by default) user verification, backed up, a counter that never moves (as Apple's and Google's
 * do), so the tests produce real WebAuthn payloads the library verifies.
 */
final class SoftwareAuthenticator
{
    public const string AAGUID = '00000000-0000-0000-0000-000000000000';

    private const int UP = 0x01;
    private const int UV = 0x04;
    private const int BE = 0x08;
    private const int BS = 0x10;
    private const int AT = 0x40;

    private readonly OpenSSLAsymmetricKey $key;
    public readonly string $credentialId;

    public function __construct(?string $credentialId = null)
    {
        $key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        if ($key === false) {
            throw new RuntimeException('openssl could not generate a P-256 key');
        }
        $this->key = $key;
        $this->credentialId = $credentialId ?? random_bytes(32);
    }

    public function credentialIdEncoded(): string
    {
        return Base64Url::encode($this->credentialId);
    }

    /**
     * The registration response (`PublicKeyCredential` JSON) for the creation options.
     *
     * @param array<string, mixed> $options
     */
    public function create(array $options, string $origin, bool $userVerified = true): string
    {
        $clientData = self::clientData('webauthn.create', (string) $options['challenge'], $origin);
        $rpId = is_array($options['rp'] ?? null) ? (string) $options['rp']['id'] : '';
        $attested = str_repeat("\0", 16) . pack('n', strlen($this->credentialId)) . $this->credentialId . $this->coseKey();
        $authData = hash('sha256', $rpId, true) . chr(self::UP | self::BE | self::BS | self::AT | ($userVerified ? self::UV : 0)) . pack('N', 0) . $attested;
        $attestation = MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create('none'))
            ->add(TextStringObject::create('attStmt'), MapObject::create())
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

        return json_encode([
            'id' => $this->credentialIdEncoded(),
            'rawId' => $this->credentialIdEncoded(),
            'type' => 'public-key',
            'authenticatorAttachment' => 'platform',
            'clientExtensionResults' => (object) [],
            'response' => [
                'clientDataJSON' => Base64Url::encode($clientData),
                'attestationObject' => Base64Url::encode((string) $attestation),
                'transports' => ['internal', 'hybrid'],
            ],
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * The assertion (`PublicKeyCredential` JSON) for the request options, signed by this credential.
     *
     * @param array<string, mixed> $options
     */
    public function get(array $options, string $origin, string $userHandle, bool $userVerified = true, int $counter = 0, ?string $challenge = null): string
    {
        $clientData = self::clientData('webauthn.get', $challenge ?? (string) $options['challenge'], $origin);
        $authData = hash('sha256', (string) ($options['rpId'] ?? ''), true) . chr(self::UP | self::BE | self::BS | ($userVerified ? self::UV : 0)) . pack('N', $counter);
        $signature = '';
        if (!openssl_sign($authData . hash('sha256', $clientData, true), $signature, $this->key, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('openssl could not sign');
        }

        return json_encode([
            'id' => $this->credentialIdEncoded(),
            'rawId' => $this->credentialIdEncoded(),
            'type' => 'public-key',
            'authenticatorAttachment' => 'platform',
            'clientExtensionResults' => (object) [],
            'response' => [
                'clientDataJSON' => Base64Url::encode($clientData),
                'authenticatorData' => Base64Url::encode($authData),
                'signature' => Base64Url::encode($signature),
                'userHandle' => Base64Url::encode($userHandle),
            ],
        ], JSON_THROW_ON_ERROR);
    }

    private static function clientData(string $type, string $challenge, string $origin): string
    {
        return json_encode(['type' => $type, 'challenge' => $challenge, 'origin' => $origin, 'crossOrigin' => false], JSON_THROW_ON_ERROR);
    }

    /**
     * The public key as a COSE_Key (EC2, P-256, ES256), CBOR-encoded.
     */
    private function coseKey(): string
    {
        $details = openssl_pkey_get_details($this->key);
        if (!is_array($details) || !is_array($details['ec'] ?? null)) {
            throw new RuntimeException('not an EC key');
        }
        $x = str_pad((string) $details['ec']['x'], 32, "\0", STR_PAD_LEFT);
        $y = str_pad((string) $details['ec']['y'], 32, "\0", STR_PAD_LEFT);

        return (string) MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create($x))
            ->add(NegativeIntegerObject::create(-3), ByteStringObject::create($y));
    }
}
