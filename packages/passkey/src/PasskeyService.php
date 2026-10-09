<?php

declare(strict_types=1);

namespace Polaris\Passkey;

use Polaris\Exception\LastFactorProtectedException;
use Polaris\Exception\MfaFactorNotFoundException;
use Polaris\Mfa\MfaConfirmation;
use Polaris\Mfa\MfaManagementService;
use Polaris\Model\MfaFactor;
use Polaris\Model\User;
use Polaris\Passkey\Factor\PasskeyFactorType;
use Polaris\Passkey\Model\Passkey;
use Polaris\Repository\UserRepository;
use Polaris\Token\ClientContext;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

use function array_map;
use function hash;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function mb_strlen;
use function random_bytes;
use function trim;

/**
 * The ceremonies: registration from a session (the credential becomes a core MFA factor when the plugin
 * enrols passkeys as factors), discoverable sign-in without one, the second-factor verification core's
 * gate delegates, and the user's list. The options of a ceremony wait in the cache under their challenge
 * and serve once; the origin the browser signed is checked before the library runs.
 */
final class PasskeyService
{
    public const string DEFAULT_NAME = 'Passkey';
    private const int MAX_NAME = 80;
    private const string REGISTER = 'register';
    private const string AUTHENTICATE = 'authenticate';

    public function __construct(
        private readonly Settings $settings,
        private readonly Protocol $protocol,
        private readonly Passkeys $passkeys,
        private readonly Sessions $sessions,
        private readonly CacheInterface $cache,
        private readonly UserRepository $users,
        private readonly MfaConfirmation $confirmation,
        private readonly MfaManagementService $factors,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @return array<string, mixed> the creation options for `navigator.credentials.create()`
     */
    public function registerOptions(User $user): array
    {
        $challenge = random_bytes(32);
        $exclude = array_map(static fn(Passkey $passkey): string => $passkey->credentialId, $this->passkeys->forUser($user->id));
        $options = $this->protocol->creationOptions($challenge, $user->id, $user->email, $user->displayName ?? $user->email, $exclude);
        $this->keep($challenge, self::REGISTER, $user->id, $options);

        return $options;
    }

    /**
     * Stores the credential the browser created; when passkeys are factors, as a confirmed core factor
     * too (the first factor answers recovery codes).
     *
     * @return array{passkey: Passkey, recovery_codes: list<string>}
     * @throws PasskeyException
     */
    public function register(User $user, #[SensitiveParameter] string $credentialJson, ?string $name): array
    {
        $name = self::name($name);
        $client = $this->clientData($credentialJson, 'webauthn.create');
        $entry = $this->take($client['challenge'], self::REGISTER);
        if ($entry['user_id'] !== $user->id) {
            throw new PasskeyException(PasskeyException::CHALLENGE_INVALID, 'The challenge was issued to another user.');
        }
        $attested = $this->protocol->attest($entry['options'], $credentialJson);
        if ($this->passkeys->byCredentialId($attested->credentialId) !== null) {
            throw new PasskeyException(PasskeyException::CREDENTIAL_INVALID, 'This credential is already registered.');
        }
        $codes = [];
        $factorId = null;
        if ($this->settings->mfaFactor) {
            $now = $this->clock->now();
            $factor = new MfaFactor();
            $factor->id = Uuid::v7()->toRfc4122();
            $factor->userId = $user->id;
            $factor->type = PasskeyFactorType::TYPE;
            $factor->label = $name;
            $factor->createdAt = $now;
            $factor->updatedAt = $now;
            $codes = $this->confirmation->complete($factor);
            $factorId = $factor->id;
        }

        return ['passkey' => $this->passkeys->create($user->id, $attested, $name, $factorId), 'recovery_codes' => $codes];
    }

    /**
     * @return array<string, mixed> the request options for `navigator.credentials.get()`, discoverable (no credential named)
     */
    public function authenticateOptions(): array
    {
        $challenge = random_bytes(32);
        $options = $this->protocol->requestOptions($challenge, []);
        $this->keep($challenge, self::AUTHENTICATE, null, $options);

        return $options;
    }

    /**
     * @return array<string, mixed> the envelope's `data`
     * @throws PasskeyException
     */
    public function authenticate(#[SensitiveParameter] string $credentialJson, ClientContext $client): array
    {
        [$passkey, $asserted] = $this->assert($credentialJson, null);
        $user = $this->users->find($passkey->userId);
        if (!$user instanceof User) {
            throw new PasskeyException(PasskeyException::CREDENTIAL_INVALID, 'The credential belongs to nobody.');
        }

        return $this->sessions->open($user, $client, $asserted->userVerified, $passkey->factorId);
    }

    /**
     * The second-factor verification: the assertion must be the passkey behind this factor.
     *
     * @throws PasskeyException
     */
    public function verifyFactor(MfaFactor $factor, #[SensitiveParameter] string $credentialJson): void
    {
        $expected = $this->passkeys->byFactor($factor->id);
        if ($expected === null || $expected->userId !== $factor->userId) {
            throw new PasskeyException(PasskeyException::CREDENTIAL_INVALID, 'No passkey backs this factor.');
        }
        [$passkey] = $this->assert($credentialJson, $expected);
        if ($passkey->id !== $expected->id) {
            throw new PasskeyException(PasskeyException::CREDENTIAL_INVALID, 'Another passkey answered.');
        }
    }

    /**
     * @return list<Passkey>
     */
    public function list(string $userId): array
    {
        return $this->passkeys->forUser($userId);
    }

    /**
     * @throws PasskeyException
     */
    public function rename(string $userId, string $id, ?string $name): Passkey
    {
        $passkey = $this->owned($userId, $id);
        $name = self::name($name);
        $this->passkeys->rename($passkey, $name);
        if ($passkey->factorId !== null) {
            try {
                $this->factors->update($userId, $passkey->factorId, $name, false);
            } catch (MfaFactorNotFoundException) {
                // The factor went away under core's route; the passkey keeps its name.
            }
        }
        $passkey->name = $name;

        return $passkey;
    }

    /**
     * Removes the passkey and the core factor it backs.
     *
     * @throws PasskeyException not the user's, or the last factor core's enforcement protects
     */
    public function delete(string $userId, string $id): void
    {
        $passkey = $this->owned($userId, $id);
        if ($passkey->factorId !== null) {
            try {
                $this->factors->remove($userId, $passkey->factorId);
            } catch (LastFactorProtectedException) {
                throw new PasskeyException(PasskeyException::LAST_FACTOR, 'Enrol another factor before removing your last one.');
            } catch (MfaFactorNotFoundException) {
                // Already removed under core's route.
            }
        }
        $this->passkeys->delete($passkey);
    }

    /**
     * Takes the challenge, finds the passkey the assertion names and verifies it; the passkey and the
     * assertion's outcome, recorded on the passkey.
     *
     * @return array{Passkey, Asserted}
     * @throws PasskeyException
     */
    private function assert(string $credentialJson, ?Passkey $expected): array
    {
        $client = $this->clientData($credentialJson, 'webauthn.get');
        $entry = $this->take($client['challenge'], self::AUTHENTICATE);
        $passkey = $this->passkeys->byCredentialId($client['id']);
        if ($passkey === null) {
            throw new PasskeyException(PasskeyException::CREDENTIAL_INVALID, 'Unknown credential.');
        }
        $asserted = $this->protocol->assert($entry['options'], $credentialJson, $passkey, ($expected ?? $passkey)->userId);
        $this->passkeys->used($passkey, $asserted);

        return [$passkey, $asserted];
    }

    /**
     * @throws PasskeyException
     */
    private function owned(string $userId, string $id): Passkey
    {
        $passkey = $this->passkeys->find($id);
        if ($passkey === null || $passkey->userId !== $userId) {
            throw new PasskeyException(PasskeyException::NOT_FOUND, 'No such passkey.');
        }

        return $passkey;
    }

    /**
     * The credential's id and the client data the browser signed: the ceremony type, the challenge and
     * the origin, which must be one of the plugin's.
     *
     * @return array{id: string, challenge: string, origin: string}
     * @throws PasskeyException
     */
    private function clientData(string $credentialJson, string $type): array
    {
        $credential = json_decode($credentialJson, true);
        $encoded = is_array($credential) ? ($credential['response']['clientDataJSON'] ?? null) : null;
        $id = is_array($credential) ? ($credential['id'] ?? $credential['rawId'] ?? null) : null;
        $data = is_string($encoded) ? json_decode((string) Base64Url::decode($encoded), true) : null;
        if (!is_string($id) || $id === '' || !is_array($data) || !is_string($data['challenge'] ?? null) || !is_string($data['origin'] ?? null)) {
            throw new PasskeyException(PasskeyException::INVALID_INPUT, 'credential must be the PublicKeyCredential JSON the browser produced.');
        }
        if (($data['type'] ?? null) !== $type) {
            throw new PasskeyException(PasskeyException::CREDENTIAL_INVALID, 'The credential is for another ceremony.');
        }
        if (!in_array($data['origin'], $this->settings->origins, true)) {
            throw new PasskeyException(PasskeyException::ORIGIN_MISMATCH, 'The credential was signed for an origin this relying party does not serve.');
        }

        return ['id' => $id, 'challenge' => $data['challenge'], 'origin' => $data['origin']];
    }

    /**
     * @param array<string, mixed> $options
     */
    private function keep(string $challenge, string $purpose, ?string $userId, array $options): void
    {
        $this->cache->set(self::key(Base64Url::encode($challenge)), ['purpose' => $purpose, 'user_id' => $userId, 'options' => $options], $this->settings->challengeTtl);
    }

    /**
     * The ceremony the challenge was issued for, once.
     *
     * @return array{purpose: string, user_id: ?string, options: array<string, mixed>}
     * @throws PasskeyException
     */
    private function take(string $challenge, string $purpose): array
    {
        $key = self::key($challenge);
        $entry = $this->cache->get($key);
        $this->cache->delete($key);
        if (!is_array($entry) || ($entry['purpose'] ?? null) !== $purpose || !is_array($entry['options'] ?? null)) {
            throw new PasskeyException(PasskeyException::CHALLENGE_INVALID, 'The challenge is unknown, used or expired.');
        }

        /** @var array{purpose: string, user_id: ?string, options: array<string, mixed>} $entry */
        return $entry;
    }

    private static function key(string $challenge): string
    {
        return 'polaris.passkey.challenge.' . hash('sha256', $challenge);
    }

    /**
     * @throws PasskeyException
     */
    private static function name(?string $name): string
    {
        $name = trim((string) $name);
        if ($name === '') {
            return self::DEFAULT_NAME;
        }
        if (mb_strlen($name) > self::MAX_NAME) {
            throw new PasskeyException(PasskeyException::INVALID_INPUT, 'name may be at most ' . self::MAX_NAME . ' characters.');
        }

        return $name;
    }
}
