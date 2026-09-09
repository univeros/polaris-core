<?php

declare(strict_types=1);

namespace Polaris\Tests\Psr15\Middleware;

use DateTimeImmutable;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\OtpConfig;
use Polaris\Contract\EncrypterInterface;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Contract\QrCodeRendererInterface;
use Polaris\Contract\RepositoryInterface;
use Polaris\Contract\SmsSenderInterface;
use Polaris\Contract\TotpProviderInterface;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\Loader;
use Polaris\Mfa\MfaChallengeVerifier;
use Polaris\Mfa\MfaConfirmation;
use Polaris\Mfa\MfaTotpService;
use Polaris\Mfa\OtpService;
use Polaris\Mfa\RecoveryCodeService;
use Polaris\Model\MfaFactor;
use Polaris\Psr15\JsonResponse;
use Polaris\Psr15\Middleware\StepUpMiddleware;
use Polaris\Psr15\Middleware\UnauthorizedResponder;
use Polaris\Security\Pepper;
use Polaris\Support\InMemoryCache;
use Polaris\Tests\Support\CountingRequestHandler;
use Polaris\Tests\Support\FrozenClock;
use Polaris\Tests\Support\InMemoryRecoveryCodeRepository;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\RecordingUnitOfWork;
use Polaris\Token\Token;
use Psr\Http\Message\ServerRequestInterface;

use function json_decode;

final class StepUpMiddlewareTest extends TestCase
{
    private const string NOW = '2026-06-09 12:00:00';
    private const int MAX_AGE = 300;

    private CountingRequestHandler $handler;

    protected function setUp(): void
    {
        $this->handler = new CountingRequestHandler();
    }

    public function testANonSensitiveRoutePassesThrough(): void
    {
        $response = $this->middleware(hasFactor: true)->process($this->authedRequest('GET', '/auth/me', authTimeAgo: 9999), $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(1, $this->handler->calls);
    }

    public function testAUserWithoutAConfirmedFactorPassesThroughEvenWhenStale(): void
    {
        $response = $this->middleware(hasFactor: false)->process($this->authedRequest('POST', '/auth/password/change', authTimeAgo: 9999), $this->handler);

        self::assertSame(200, $response->getStatusCode(), 'step-up does not apply without MFA');
    }

    public function testRecentAuthPassesThrough(): void
    {
        $response = $this->middleware(hasFactor: true)->process($this->authedRequest('POST', '/auth/password/change', authTimeAgo: 100), $this->handler);

        self::assertSame(200, $response->getStatusCode());
    }

    public function testStaleOrMissingAuthTimeIsRejectedWithStepUpRequired(): void
    {
        $response = $this->middleware(hasFactor: true)->process($this->authedRequest('POST', '/auth/password/change', authTimeAgo: 600), $this->handler);

        self::assertSame(401, $response->getStatusCode());
        self::assertStringContainsString('step_up_required', (string) $response->getBody());
        self::assertSame('/auth/mfa/step-up', json_decode((string) $response->getBody(), true)['step_up'] ?? null);
        self::assertStringContainsString('step_up_required', $response->getHeaderLine('WWW-Authenticate'));
        self::assertSame(401, $this->middleware(hasFactor: true)->process($this->authedRequest('POST', '/auth/password/change', authTimeAgo: null), $this->handler)->getStatusCode());
        self::assertSame(0, $this->handler->calls, 'the sensitive endpoint is never reached');
    }

    public function testAnUnauthenticatedRequestFailsClosed(): void
    {
        $response = $this->middleware(hasFactor: true)->process($this->routed('POST', '/auth/password/change'), $this->handler);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(0, $this->handler->calls);
    }

    private function middleware(bool $hasFactor): StepUpMiddleware
    {
        return new StepUpMiddleware(
            $this->verifier($hasFactor),
            AuthConfig::fromArray(['issuer' => 'https://auth.polaris.test', 'step_up' => ['max_age' => self::MAX_AGE]]),
            FrozenClock::at(self::NOW),
            new UnauthorizedResponder(new ResponseFactory()),
            new JsonResponse(new ResponseFactory()),
        );
    }

    private function verifier(bool $hasFactor): MfaChallengeVerifier
    {
        $factors = $this->createStub(RepositoryInterface::class);
        $factors->method('findBy')->willReturn($hasFactor ? [$this->confirmedFactor()] : []);
        $clock = FrozenClock::at(self::NOW);
        $uow = new RecordingUnitOfWork();
        $pepper = new Pepper('app-key-for-tests-0123456789abcdef');
        $recovery = new RecoveryCodeService(new InMemoryRecoveryCodeRepository($uow), $uow, $pepper, $clock, new RecordingEventDispatcher());
        $confirmation = new MfaConfirmation($factors, $recovery, $uow, $clock, new RecordingEventDispatcher());
        $totp = new MfaTotpService($factors, $this->createStub(TotpProviderInterface::class), $this->createStub(EncrypterInterface::class), $this->createStub(QrCodeRendererInterface::class), $confirmation, $uow, $clock);
        $otp = new OtpService($this->createStub(RepositoryInterface::class), $this->createStub(SmsSenderInterface::class), $this->createStub(OtpMailerInterface::class), $pepper, OtpConfig::fromArray([]), $uow, $clock, new RecordingEventDispatcher(), new InMemoryCache());

        return new MfaChallengeVerifier($factors, $totp, $otp, $recovery);
    }

    private function confirmedFactor(): MfaFactor
    {
        $now = new DateTimeImmutable(self::NOW);
        $factor = new MfaFactor();
        $factor->id = 'f-1';
        $factor->userId = 'user-1';
        $factor->type = MfaFactor::TYPE_TOTP;
        $factor->confirmedAt = $now;
        $factor->createdAt = $now;
        $factor->updatedAt = $now;

        return $factor;
    }

    private function authedRequest(string $method, string $path, ?int $authTimeAgo): ServerRequestInterface
    {
        $now = (new DateTimeImmutable(self::NOW))->getTimestamp();
        $claims = ['sub' => 'user-1'];
        if ($authTimeAgo !== null) {
            $claims['auth_time'] = $now - $authTimeAgo;
        }

        return $this->routed($method, $path)->withAttribute(Attributes::TOKEN, new Token('jwt', $claims));
    }

    private function routed(string $method, string $path): ServerRequestInterface
    {
        $spec = (new Loader(Loader::defaultDirectory()))->load()->find($method, $path);
        self::assertNotNull($spec);

        return (new ServerRequestFactory())->createServerRequest($method, $path)->withAttribute(Attributes::ROUTE, $spec);
    }
}
