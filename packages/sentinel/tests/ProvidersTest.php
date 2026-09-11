<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Tests;

use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Messaging\Tests\Support\FakeHttpClient;
use Polaris\Sentinel\Http\ResponseFactories;
use Polaris\Sentinel\Provider\FileDomainList;
use Polaris\Sentinel\Provider\GeoPoint;
use Polaris\Sentinel\Provider\HcaptchaVerifier;
use Polaris\Sentinel\Provider\HibpBreachChecker;
use Polaris\Sentinel\Provider\MaxMindGeoResolver;
use Polaris\Sentinel\Provider\NullChecker;
use Polaris\Sentinel\Provider\NullResolver;
use Polaris\Sentinel\Provider\NullVerifier;
use Polaris\Sentinel\Provider\SiteVerifier;
use Polaris\Sentinel\Provider\TurnstileVerifier;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

use function file_put_contents;
use function sha1;
use function strtoupper;
use function substr;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

/**
 * The shipped providers over PSR-18 with a fake client, the list file, the geometry.
 */
#[CoversClass(SiteVerifier::class)]
#[CoversClass(TurnstileVerifier::class)]
#[CoversClass(HcaptchaVerifier::class)]
#[CoversClass(HibpBreachChecker::class)]
#[CoversClass(FileDomainList::class)]
#[CoversClass(GeoPoint::class)]
#[CoversClass(MaxMindGeoResolver::class)]
#[CoversClass(NullResolver::class)]
#[CoversClass(NullVerifier::class)]
#[CoversClass(NullChecker::class)]
#[CoversClass(ResponseFactories::class)]
final class ProvidersTest extends TestCase
{
    public function testTheSiteVerifiersPostTheSecretTheTokenAndTheAddress(): void
    {
        $client = new FakeHttpClient(200, '{"success": true}');
        $turnstile = new TurnstileVerifier($client, new RequestFactory(), new StreamFactory(), 'secret-1');
        self::assertTrue($turnstile->verify('tok', '203.0.113.7'));
        $request = $client->requests[0];
        self::assertSame(['POST', 'https://challenges.cloudflare.com/turnstile/v0/siteverify', 'application/x-www-form-urlencoded'], [$request->getMethod(), (string) $request->getUri(), $request->getHeaderLine('Content-Type')]);
        self::assertSame('secret=secret-1&response=tok&remoteip=203.0.113.7', (string) $request->getBody());

        $hcaptcha = new HcaptchaVerifier(new FakeHttpClient(200, '{"success": false, "error-codes": ["invalid-input-response"]}'), new RequestFactory(), new StreamFactory(), 's');
        self::assertFalse($hcaptcha->verify('tok', null));
        self::assertFalse((new TurnstileVerifier(new FakeHttpClient(500, ''), new RequestFactory(), new StreamFactory(), 's'))->verify('tok', null));
        self::assertFalse((new TurnstileVerifier(self::failingClient(), new RequestFactory(), new StreamFactory(), 's'))->verify('tok', null), 'a transport failure fails the verification');
        self::assertFalse((new NullVerifier())->verify('tok', null));
    }

    public function testHibpLooksUpTheRangeAndMatchesTheSuffix(): void
    {
        $hash = strtoupper(sha1('password1'));
        $body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\n" . substr($hash, 5) . ":2427\n" . "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\n";
        $client = new FakeHttpClient(200, $body);
        $checker = new HibpBreachChecker($client, new RequestFactory());

        self::assertTrue($checker->isBreached('password1'));
        self::assertSame('https://api.pwnedpasswords.com/range/' . substr($hash, 0, 5), (string) $client->requests[0]->getUri());
        self::assertSame('true', $client->requests[0]->getHeaderLine('Add-Padding'));
        self::assertFalse($checker->isBreached('correct horse battery staple'), 'the suffix is not in the range');
        self::assertFalse((new HibpBreachChecker(new FakeHttpClient(503, ''), new RequestFactory()))->isBreached('password1'));
        self::assertFalse((new HibpBreachChecker(self::failingClient(), new RequestFactory()))->isBreached('password1'), 'advisory: a transport failure is not a breach');
        self::assertFalse((new NullChecker())->isBreached('password1'));
    }

    public function testTheDomainListReadsAFileWithCommentsAndTheExtras(): void
    {
        $file = (string) tempnam(sys_get_temp_dir(), 'polaris-domains');
        file_put_contents($file, "# a comment\nTrash.Example\n\n  other.example  \n");
        try {
            $list = new FileDomainList($file, ['Third.Example']);
            self::assertTrue($list->contains('trash.example'));
            self::assertTrue($list->contains('OTHER.example'));
            self::assertTrue($list->contains('third.example'));
            self::assertFalse($list->contains('example.com'));
            self::assertFalse($list->contains('mailinator.com'), 'the bundled list is not read when a file is given');
        } finally {
            unlink($file);
        }
        self::assertFalse((new FileDomainList('/nowhere/list.txt'))->contains('mailinator.com'), 'a missing file is an empty list');
        self::assertTrue((new FileDomainList())->contains('mailinator.com'), 'the bundled list');
    }

    public function testGeometryAndTheResolversWithoutADatabase(): void
    {
        $paris = new GeoPoint(48.8566, 2.3522);
        $newYork = new GeoPoint(40.7128, -74.0060);
        self::assertEqualsWithDelta(5837.0, $paris->distanceTo($newYork), 5.0);
        self::assertSame(0.0, $paris->distanceTo($paris));
        self::assertNull((new NullResolver())->resolve('203.0.113.7'));
        self::assertNull((new MaxMindGeoResolver('/nowhere/GeoLite2-City.mmdb'))->resolve('203.0.113.7'), 'an unreadable database resolves nothing');
    }

    public function testAResponseFactoryIsDiscovered(): void
    {
        self::assertInstanceOf(ResponseFactoryInterface::class, ResponseFactories::discover());
    }

    private static function failingClient(): ClientInterface
    {
        return new class implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                throw new class ('down') extends RuntimeException implements ClientExceptionInterface {
                };
            }
        };
    }
}
