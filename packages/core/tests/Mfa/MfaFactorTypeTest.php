<?php

declare(strict_types=1);

namespace Polaris\Tests\Mfa;

use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Exception\InvalidOtpException;
use Polaris\Exception\MfaFactorNotFoundException;
use Polaris\Mfa\ChallengePurpose;
use Polaris\Mfa\MfaChallengeVerifier;
use Polaris\Model\MfaFactor;
use Polaris\Model\User;
use Polaris\Polaris;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\FrozenClock;
use Polaris\Tests\Support\Plugin\StampFactorType;
use Polaris\Tests\Support\Plugin\StampPlugin;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\ClientContext;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Symfony\Component\Uid\Uuid;

use function str_repeat;

/**
 * The factor-type seam (program 4, decision #1): a plugin's type verifies its own factor rows through
 * core's gate and step-up, a type nobody verifies is unusable, core's own types cannot be replaced, and
 * a plugin type has no sent challenge. Separate processes: the schema registry is static.
 */
#[CoversClass(MfaChallengeVerifier::class)]
#[CoversClass(Graph::class)]
#[RunTestsInSeparateProcesses]
final class MfaFactorTypeTest extends TestCase
{
    private const string NOW = '2026-10-09T10:00:00+00:00';

    public function testAPluginsTypeClearsTheGateAndStepUpWithItsOwnVerification(): void
    {
        $type = new StampFactorType();
        $graph = self::polaris(new StampPlugin([$type]))->graph();
        $user = self::user($graph);
        $factor = self::factor($graph, $user->id, 'stamp');
        $client = new ClientContext('203.0.113.7', 'ua/1');

        $gate = $graph->mfaLogin();
        self::assertSame('stamp', $gate->confirmedFactors($user->id)[0]->type, 'core lists the plugin\'s factor');
        $tokens = $gate->verify($user->id, $factor->id, 'stamp:' . $factor->id, $client);
        self::assertSame([[$factor->id, 'stamp:' . $factor->id, ChallengePurpose::LoginMfa]], $type->verified);
        $claims = $graph->tokenFactory()->fromTokenString($tokens->accessToken)->getMetadata();
        self::assertSame([['pwd', 'otp'], true], [$claims['amr'], $claims['mfa']], 'core\'s post-MFA session');

        try {
            $gate->verify($user->id, $factor->id, 'wrong', $client);
            self::fail('the type refused');
        } catch (InvalidOtpException) {
            self::addToAssertionCount(1);
        }
        $stepUp = $graph->stepUp()->verify($user->id, null, $tokens->sessionId, $factor->id, 'stamp:' . $factor->id);
        $verified = $type->verifications();
        self::assertCount(3, $verified);
        self::assertSame(ChallengePurpose::StepUp, $verified[2][2]);
        self::assertNotSame('', $stepUp);

        try {
            $gate->challenge($user->id, $factor->id, $client);
            self::fail('no sent challenge for a plugin type');
        } catch (InvalidOtpException) {
            self::addToAssertionCount(1);
        }
    }

    public function testAFactorOfATypeNobodyVerifiesIsUnusable(): void
    {
        $graph = self::polaris()->graph();
        $user = self::user($graph);
        $factor = self::factor($graph, $user->id, 'stamp');

        $this->expectException(MfaFactorNotFoundException::class);
        $graph->mfaLogin()->verify($user->id, $factor->id, 'stamp:' . $factor->id, new ClientContext(null, null));
    }

    public function testCoresOwnTypesAndADuplicateCannotBeRegistered(): void
    {
        foreach ([[new StampFactorType('totp')], [new StampFactorType(), new StampFactorType()]] as $types) {
            $graph = self::polaris(new StampPlugin($types))->graph();
            $user = self::user($graph);
            $factor = self::factor($graph, $user->id, 'stamp');
            try {
                // The types are resolved on the first verification (a type may be built from the MFA services).
                $graph->mfaVerifier()->verify($user->id, $factor->id, 'x', ChallengePurpose::LoginMfa);
                self::fail('refused');
            } catch (LogicException $exception) {
                self::assertStringContainsString('already verifies', $exception->getMessage());
            }
        }
    }

    private static function user(Graph $graph): User
    {
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = 'ada@example.com';
        $user->emailVerifiedAt = new DateTimeImmutable(self::NOW);
        $user->createdAt = $user->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();

        return $user;
    }

    private static function factor(Graph $graph, string $userId, string $type): MfaFactor
    {
        $factor = new MfaFactor();
        $factor->id = Uuid::v7()->toRfc4122();
        $factor->userId = $userId;
        $factor->type = $type;
        $factor->label = 'YubiKey';
        $factor->isDefault = true;
        $factor->confirmedAt = new DateTimeImmutable(self::NOW);
        $factor->createdAt = $factor->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($factor);
        $graph->unitOfWork()->flush();

        return $factor;
    }

    private static function polaris(?StampPlugin $plugin = null): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: new FrozenClock(new DateTimeImmutable(self::NOW)),
            plugins: $plugin === null ? [] : [$plugin],
        ));
    }
}
