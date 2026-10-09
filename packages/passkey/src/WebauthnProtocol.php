<?php

declare(strict_types=1);

namespace Polaris\Passkey;

use Override;
use Polaris\Passkey\Model\Passkey;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

use function array_map;
use function is_array;
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * WebAuthn through `web-auth/webauthn-lib`: creation and request options serialised as the browser takes
 * them, the attestation and assertion ceremonies checked against the plugin's relying party and origins
 * (`none` attestation: the authenticator's make is not verified), ES256 and RS256 keys.
 */
final class WebauthnProtocol implements Protocol
{
    private const int ES256 = -7;
    private const int RS256 = -257;

    private readonly SerializerInterface $serializer;
    private readonly AuthenticatorAttestationResponseValidator $attestations;
    private readonly AuthenticatorAssertionResponseValidator $assertions;

    public function __construct(private readonly Settings $settings)
    {
        $statements = AttestationStatementSupportManager::create([new NoneAttestationStatementSupport()]);
        $this->serializer = (new WebauthnSerializerFactory($statements))->create();
        $ceremonies = new CeremonyStepManagerFactory();
        $ceremonies->setAttestationStatementSupportManager($statements);
        $ceremonies->setAllowedOrigins($settings->origins);
        $ceremonies->setSecuredRelyingPartyId($settings->insecureHosts());
        $this->attestations = AuthenticatorAttestationResponseValidator::create($ceremonies->creationCeremony());
        $this->assertions = AuthenticatorAssertionResponseValidator::create($ceremonies->requestCeremony());
    }

    #[Override]
    public function creationOptions(string $challenge, string $userId, string $userName, string $displayName, array $excludeCredentialIds): array
    {
        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create($this->settings->rpName, $this->settings->rpId),
            PublicKeyCredentialUserEntity::create($userName, $userId, $displayName),
            $challenge,
            [PublicKeyCredentialParameters::createPk(self::ES256), PublicKeyCredentialParameters::createPk(self::RS256)],
            AuthenticatorSelectionCriteria::create($this->settings->attachment, $this->settings->userVerification, AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            array_map(self::descriptor(...), $excludeCredentialIds),
            $this->settings->timeout,
        );

        return $this->toArray($options);
    }

    #[Override]
    public function requestOptions(string $challenge, array $allowCredentialIds): array
    {
        $options = PublicKeyCredentialRequestOptions::create(
            $challenge,
            $this->settings->rpId,
            array_map(self::descriptor(...), $allowCredentialIds),
            $this->settings->userVerification,
            $this->settings->timeout,
        );

        return $this->toArray($options);
    }

    #[Override]
    public function attest(array $options, string $credentialJson): Attested
    {
        try {
            $credential = $this->serializer->deserialize($credentialJson, PublicKeyCredential::class, 'json');
            $response = $credential->response;
            if (!$response instanceof AuthenticatorAttestationResponse) {
                throw new PasskeyException(PasskeyException::CREDENTIAL_INVALID, 'The credential is not a registration.');
            }
            $creation = $this->serializer->deserialize(json_encode($options, JSON_THROW_ON_ERROR), PublicKeyCredentialCreationOptions::class, 'json');
            $record = $this->attestations->check($response, $creation, $this->settings->rpId);
        } catch (PasskeyException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new PasskeyException(PasskeyException::CREDENTIAL_INVALID, 'The registration could not be verified: ' . $exception->getMessage(),);
        }
        $flags = $response->attestationObject->authData;

        return new Attested(
            Base64Url::encode($record->publicKeyCredentialId),
            Base64Url::encode($record->credentialPublicKey),
            $record->counter,
            (string) $record->aaguid,
            $record->transports,
            $flags->isBackupEligible(),
            $flags->isBackedUp(),
            $flags->isUserVerified(),
        );
    }

    #[Override]
    public function assert(array $options, string $credentialJson, Passkey $passkey, string $userHandle): Asserted
    {
        try {
            $credential = $this->serializer->deserialize($credentialJson, PublicKeyCredential::class, 'json');
            $response = $credential->response;
            if (!$response instanceof AuthenticatorAssertionResponse) {
                throw new PasskeyException(PasskeyException::CREDENTIAL_INVALID, 'The credential is not an assertion.');
            }
            $request = $this->serializer->deserialize(json_encode($options, JSON_THROW_ON_ERROR), PublicKeyCredentialRequestOptions::class, 'json');
            $record = CredentialRecord::create(
                (string) Base64Url::decode($passkey->credentialId),
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $passkey->transports,
                'none',
                EmptyTrustPath::create(),
                Uuid::fromString($passkey->aaguid),
                (string) Base64Url::decode($passkey->publicKey),
                $userHandle,
                $passkey->counter,
                null,
                $passkey->backupEligible,
                $passkey->backedUp,
            );
            $updated = $this->assertions->check($record, $response, $request, $this->settings->rpId, $userHandle);
        } catch (PasskeyException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new PasskeyException(PasskeyException::CREDENTIAL_INVALID, 'The assertion could not be verified: ' . $exception->getMessage());
        }

        return new Asserted($updated->counter, $response->authenticatorData->isBackedUp(), $response->authenticatorData->isUserVerified());
    }

    private static function descriptor(string $credentialId): PublicKeyCredentialDescriptor
    {
        return PublicKeyCredentialDescriptor::create(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, (string) Base64Url::decode($credentialId));
    }

    /**
     * @return array<string, mixed>
     */
    private function toArray(PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions $options): array
    {
        $decoded = json_decode($this->serializer->serialize($options, 'json', [AbstractObjectNormalizer::SKIP_NULL_VALUES => true]), true, 512, JSON_THROW_ON_ERROR);

        return is_array($decoded) ? $decoded : [];
    }
}
