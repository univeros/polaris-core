<?php

declare(strict_types=1);

namespace Polaris\Security;

use InvalidArgumentException;
use Override;
use Polaris\Contract\EncrypterInterface;
use Polaris\Exception\DecryptException;
use SensitiveParameter;

use function base64_decode;
use function base64_encode;
use function hash_hkdf;
use function is_scalar;
use function random_bytes;
use function sodium_crypto_aead_xchacha20poly1305_ietf_decrypt;
use function sodium_crypto_aead_xchacha20poly1305_ietf_encrypt;
use function strlen;
use function substr;

use const SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
use const SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
use const SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

/**
 * XChaCha20-Poly1305 (libsodium) with a key derived from the application key by HKDF-SHA256.
 *
 * Payload: base64( version byte . 24-byte nonce . ciphertext+tag ). Scalars only: the one
 * thing Polaris encrypts at rest is the TOTP seed.
 */
final class SodiumEncrypter implements EncrypterInterface
{
    private const string VERSION = "\x01";
    private const string KEY_CONTEXT = 'polaris:encrypter:mfa';

    private readonly string $key;

    public function __construct(#[SensitiveParameter] string $appKey)
    {
        if ($appKey === '') {
            throw new InvalidArgumentException('SodiumEncrypter requires a non-empty application key.');
        }

        $this->key = hash_hkdf('sha256', $appKey, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, self::KEY_CONTEXT);
    }

    #[Override]
    public function encrypt(mixed $value): string
    {
        if (!is_scalar($value)) {
            throw new InvalidArgumentException('SodiumEncrypter encrypts scalar values only.');
        }

        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt((string) $value, self::VERSION, $nonce, $this->key);

        return base64_encode(self::VERSION . $nonce . $cipher);
    }

    #[Override]
    public function decrypt(string $payload): string
    {
        $raw = base64_decode($payload, true);
        $minimum = 1 + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
        if ($raw === false || strlen($raw) < $minimum || $raw[0] !== self::VERSION) {
            throw new DecryptException('The encrypted payload is malformed.');
        }

        $nonce = substr($raw, 1, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $cipher = substr($raw, 1 + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, self::VERSION, $nonce, $this->key);
        if ($plain === false) {
            throw new DecryptException('The encrypted payload could not be authenticated.');
        }

        return $plain;
    }
}
