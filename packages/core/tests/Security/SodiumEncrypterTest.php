<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Security;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Exception\DecryptException;
use Polaris\Security\SodiumEncrypter;

use function base64_decode;
use function base64_encode;
use function str_repeat;
use function strlen;

#[CoversClass(SodiumEncrypter::class)]
final class SodiumEncrypterTest extends TestCase
{
    private const string APP_KEY = 'base64:0123456789abcdef0123456789abcdef';

    public function testRoundTripsAndNeverRepeatsCiphertext(): void
    {
        $encrypter = new SodiumEncrypter(self::APP_KEY);

        $first = $encrypter->encrypt('JBSWY3DPEHPK3PXP');
        $second = $encrypter->encrypt('JBSWY3DPEHPK3PXP');

        self::assertSame('JBSWY3DPEHPK3PXP', $encrypter->decrypt($first));
        self::assertNotSame($first, $second, 'a fresh nonce per call');
        self::assertSame('42', $encrypter->decrypt($encrypter->encrypt(42)));
    }

    public function testRejectsTamperedPayload(): void
    {
        $encrypter = new SodiumEncrypter(self::APP_KEY);
        $raw = (string) base64_decode($encrypter->encrypt('secret'), true);
        $raw[strlen($raw) - 1] = $raw[strlen($raw) - 1] === 'a' ? 'b' : 'a';

        $this->expectException(DecryptException::class);
        $encrypter->decrypt(base64_encode($raw));
    }

    public function testRejectsPayloadFromAnotherKey(): void
    {
        $payload = (new SodiumEncrypter(self::APP_KEY))->encrypt('secret');

        $this->expectException(DecryptException::class);
        (new SodiumEncrypter('another-key'))->decrypt($payload);
    }

    public function testRejectsMalformedPayload(): void
    {
        $encrypter = new SodiumEncrypter(self::APP_KEY);

        $this->expectException(DecryptException::class);
        $encrypter->decrypt(base64_encode(str_repeat("\x02", 60)));
    }

    public function testRequiresAKeyAndScalarValues(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new SodiumEncrypter('');
    }

    public function testRejectsNonScalarValues(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new SodiumEncrypter(self::APP_KEY))->encrypt(['not' => 'scalar']);
    }
}
