<?php

declare(strict_types=1);

namespace Polaris\Tests\Persistence;

use Polaris\Repository\RecoveryCodeRepository;
use Polaris\Repository\OtpChallengeRepository;
use Polaris\Repository\MfaFactorRepository;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Polaris\Model\MfaFactor;
use Polaris\Model\OtpChallenge;
use Polaris\Model\RecoveryCode;
use Polaris\Mfa\ChallengePurpose;

use function str_repeat;

/**
 * Verifies the #17 MFA/OTP entities and migrations against a real database driver: the
 * migrations create the expected portable tables, columns, and indexes; the attribute-mapped
 * entities round-trip through them; and the migrations roll back cleanly.
 */
final class MfaEntitiesPersistenceTest extends DatabaseTestCase
{
    public function testMigrationsCreateTheMfaTablesWithIndexes(): void
    {
        $database = $this->adapter;

        self::assertTrue($this->hasTable('auth_mfa_factors'));
        self::assertTrue($this->hasTable('auth_otp_challenges'));
        self::assertTrue($this->hasTable('auth_recovery_codes'));

        $factors = 'auth_mfa_factors';
        foreach (['id', 'user_id', 'type', 'secret_encrypted', 'is_default', 'confirmed_at'] as $column) {
            self::assertTrue($this->hasColumn($factors, $column), "auth_mfa_factors.$column should exist");
        }
        self::assertTrue($this->hasIndex($factors, ['user_id', 'type']));
        self::assertTrue($this->hasIndex($factors, ['user_id', 'confirmed_at']));

        $challenges = 'auth_otp_challenges';
        foreach (['id', 'user_id', 'purpose', 'channel', 'code_hash', 'attempts', 'max_attempts', 'expires_at'] as $column) {
            self::assertTrue($this->hasColumn($challenges, $column), "auth_otp_challenges.$column should exist");
        }
        self::assertTrue($this->hasIndex($challenges, ['user_id', 'purpose', 'consumed_at']));
        self::assertTrue($this->hasIndex($challenges, ['expires_at']));

        $codes = 'auth_recovery_codes';
        foreach (['id', 'user_id', 'code_hash', 'used_at', 'created_at'] as $column) {
            self::assertTrue($this->hasColumn($codes, $column), "auth_recovery_codes.$column should exist");
        }
        self::assertTrue($this->hasIndex($codes, ['user_id', 'used_at']));
    }

    public function testMfaFactorRoundTrips(): void
    {
        $repository = new MfaFactorRepository($this->adapter, $this->identities);
        $now = new DateTimeImmutable('2026-06-08 10:00:00');

        $factor = new MfaFactor();
        $factor->id = Uuid::v7()->toRfc4122();
        $factor->userId = Uuid::v7()->toRfc4122();
        $factor->type = MfaFactor::TYPE_TOTP;
        $factor->label = 'iPhone Authenticator';
        $factor->secretEncrypted = str_repeat('x', 200);
        $factor->isDefault = true;
        $factor->confirmedAt = $now;
        $factor->createdAt = $now;
        $factor->updatedAt = $now;
        $this->unitOfWork->persist($factor);
        $this->unitOfWork->flush();

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['id' => $factor->id]);

        self::assertInstanceOf(MfaFactor::class, $found);
        self::assertSame($factor->userId, $found->userId);
        self::assertSame(MfaFactor::TYPE_TOTP, $found->type);
        self::assertSame('iPhone Authenticator', $found->label);
        self::assertSame(str_repeat('x', 200), $found->secretEncrypted);
        self::assertTrue($found->isDefault);
        self::assertInstanceOf(DateTimeImmutable::class, $found->confirmedAt);
        self::assertNull($found->phoneE164);
    }

    public function testOtpChallengeRoundTrips(): void
    {
        $repository = new OtpChallengeRepository($this->adapter, $this->identities);
        $now = new DateTimeImmutable('2026-06-08 10:00:00');
        $hash = str_repeat('b', 64);

        $challenge = new OtpChallenge();
        $challenge->id = Uuid::v7()->toRfc4122();
        $challenge->userId = Uuid::v7()->toRfc4122();
        $challenge->purpose = ChallengePurpose::LoginMfa->value;
        $challenge->channel = OtpChallenge::CHANNEL_SMS;
        $challenge->codeHash = $hash;
        $challenge->destination = '+15551234567';
        $challenge->expiresAt = $now->modify('+5 minutes');
        $challenge->createdAt = $now;
        $this->unitOfWork->persist($challenge);
        $this->unitOfWork->flush();

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['codeHash' => $hash]);

        self::assertInstanceOf(OtpChallenge::class, $found);
        self::assertSame($challenge->userId, $found->userId);
        self::assertSame(ChallengePurpose::LoginMfa->value, $found->purpose);
        self::assertSame(OtpChallenge::CHANNEL_SMS, $found->channel);
        self::assertSame(0, $found->attempts);
        self::assertSame(5, $found->maxAttempts);
        self::assertNull($found->factorId);
        self::assertNull($found->consumedAt);
        self::assertInstanceOf(DateTimeImmutable::class, $found->expiresAt);
    }

    public function testRecoveryCodeRoundTrips(): void
    {
        $repository = new RecoveryCodeRepository($this->adapter, $this->identities);
        $now = new DateTimeImmutable('2026-06-08 10:00:00');
        $hash = str_repeat('c', 64);

        $code = new RecoveryCode();
        $code->id = Uuid::v7()->toRfc4122();
        $code->userId = Uuid::v7()->toRfc4122();
        $code->codeHash = $hash;
        $code->createdAt = $now;
        $this->unitOfWork->persist($code);
        $this->unitOfWork->flush();

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['codeHash' => $hash]);

        self::assertInstanceOf(RecoveryCode::class, $found);
        self::assertSame($code->userId, $found->userId);
        self::assertNull($found->usedAt);
        self::assertInstanceOf(DateTimeImmutable::class, $found->createdAt);
    }
}
