<?php

declare(strict_types=1);

namespace Polaris\Scim;

use DateTimeImmutable;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Event\MemberJoined;
use Polaris\Identity\EmailNormalizer;
use Polaris\Identity\UserAdminService;
use Polaris\Model\Membership;
use Polaris\Model\MembershipRole;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\Model\Resource;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

use function array_slice;
use function count;
use function filter_var;
use function is_array;
use function is_bool;
use function is_string;
use function strlen;
use function trim;
use function usort;

use const DATE_ATOM;
use const FILTER_VALIDATE_EMAIL;

/**
 * SCIM Users onto Polaris users who are members of the connection's organization: `userName` and the
 * primary email are the email, `displayName`/`name.formatted` the display name, `active` the account
 * status, `externalId` the directory's own id. A created user is verified and has no password; a
 * deprovisioned one is deactivated (every session ends) or, when the connection says so, anonymised.
 */
final class Users
{
    public const string SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
    public const string DEFAULT_ROLE = 'member';
    public const string ACTOR = 'scim';

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly UserRepository $users,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly UserAdminService $admin,
        private readonly Resources $resources,
        private readonly EventDispatcherInterface $events,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * The organization's members, filtered and paged (`startIndex` is 1-based).
     *
     * @return array{total: int, resources: list<array<string, mixed>>}
     */
    public function list(Connection $connection, Filter $filter, int $startIndex, int $count, string $location): array
    {
        // ponytail: every member is loaded and filtered in memory; a store-side filter comes with the first organization above a few thousand members.
        $matches = [];
        foreach ($this->database->findMany('auth_memberships', ['organization_id' => $connection->organizationId], ['id' => 'asc']) as $membership) {
            $user = $this->users->find((string) $membership['user_id']);
            if (!$user instanceof User) {
                continue;
            }
            $resource = $this->resource($connection, $user, $location);
            if ($filter->matches(self::flat($resource))) {
                $matches[] = $resource;
            }
        }
        usort($matches, static fn(array $a, array $b): int => (string) $a['id'] <=> (string) $b['id']);

        return ['total' => count($matches), 'resources' => array_slice($matches, $startIndex - 1, $count)];
    }

    /**
     * @throws ScimError
     */
    public function find(Connection $connection, string $id): User
    {
        $user = $this->users->find($id);
        if (!$user instanceof User || $this->membership($connection, $user->id) === null) {
            throw ScimError::notFound('User');
        }

        return $user;
    }

    /**
     * @param array<string, mixed> $body
     * @throws ScimError
     */
    public function create(Connection $connection, array $body): User
    {
        $email = self::email($body);
        $existing = $this->users->findOneBy(['email' => $email]);
        if ($existing instanceof User && $this->membership($connection, $existing->id) !== null) {
            throw ScimError::conflict('A member with this userName exists.');
        }
        $now = $this->clock->now();
        $user = $existing;
        if (!$user instanceof User) {
            $user = new User();
            $user->id = Uuid::v7()->toRfc4122();
            $user->email = $email;
            $user->emailVerifiedAt = $now;
            $user->createdAt = $now;
        }
        $user->displayName = self::displayName($body) ?? $user->displayName;
        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();
        $this->join($connection, $user);
        $this->resources->setExternalId($connection, Resource::USER, $user->id, self::externalId($body));
        if (($body['active'] ?? true) === false) {
            $this->admin->disable(self::ACTOR, $user->id);
        }

        return $this->reload($user->id);
    }

    /**
     * PUT: the body replaces the attributes the package maps; the rest is ignored.
     *
     * @param array<string, mixed> $body
     * @throws ScimError
     */
    public function replace(Connection $connection, User $user, array $body): User
    {
        $email = self::email($body);
        $this->rename($user, $email);
        $user->displayName = self::displayName($body);
        $user->updatedAt = $this->clock->now();
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();
        $this->resources->setExternalId($connection, Resource::USER, $user->id, self::externalId($body));
        $this->setActive($connection, $user, ($body['active'] ?? true) !== false);

        return $this->reload($user->id);
    }

    /**
     * PATCH: the operations touch `active`, `userName`, `displayName`, `name.*` and `externalId`.
     *
     * @param list<array{string, string|null, mixed}> $operations
     * @throws ScimError
     */
    public function patch(Connection $connection, User $user, array $operations): User
    {
        foreach ($operations as $operation) {
            $active = Patch::scalar($operation, 'active');
            if ($active !== null) {
                $this->setActive($connection, $user, filter_var($active, FILTER_VALIDATE_BOOLEAN));
                $user = $this->reload($user->id);
            }
            $userName = Patch::scalar($operation, 'userName');
            if (is_string($userName)) {
                $this->rename($user, self::validEmail($userName));
            }
            foreach (['displayName', 'name.formatted'] as $attribute) {
                $name = Patch::scalar($operation, $attribute);
                if ($name !== null) {
                    $user->displayName = is_string($name) && trim($name) !== '' ? trim($name) : null;
                }
            }
            $given = Patch::scalar($operation, 'name.givenName');
            $family = Patch::scalar($operation, 'name.familyName');
            if (is_string($given) || is_string($family)) {
                $user->displayName = trim((is_string($given) ? $given : '') . ' ' . (is_string($family) ? $family : ''));
            }
            $externalId = Patch::scalar($operation, 'externalId');
            if ($externalId !== null || ($operation[0] === 'remove' && $operation[1] !== null && Patch::stripUrn($operation[1]) === 'externalId')) {
                $this->resources->setExternalId($connection, Resource::USER, $user->id, is_string($externalId) ? $externalId : null);
            }
        }
        $user->updatedAt = $this->clock->now();
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();

        return $this->reload($user->id);
    }

    /**
     * DELETE: what the connection's `deprovision` says; a membership the connection did not create stays.
     *
     * @return string `deactivated` or `deleted`
     */
    public function delete(Connection $connection, User $user): string
    {
        if ($connection->deprovision() === Connection::DELETE) {
            $this->admin->anonymize(self::ACTOR, $user->id);
            $this->resources->forget($connection, Resource::USER, $user->id);
            $this->resources->forgetMembership($connection, $user->id);

            return 'deleted';
        }
        $this->admin->disable(self::ACTOR, $user->id);
        if ($this->resources->createdMembership($connection, $user->id)) {
            $membership = $this->membership($connection, $user->id);
            if ($membership !== null) {
                $this->database->delete('auth_membership_roles', ['membership_id' => $membership['id']]);
                $this->database->delete('auth_memberships', ['id' => $membership['id']]);
            }
            $this->resources->forgetMembership($connection, $user->id);
        }
        $this->resources->forget($connection, Resource::USER, $user->id);

        return 'deactivated';
    }

    /**
     * @return array<string, mixed>
     */
    public function resource(Connection $connection, User $user, string $location): array
    {
        $roles = [];
        $membership = $this->membership($connection, $user->id);
        foreach ($membership === null ? [] : $this->database->findMany('auth_membership_roles', ['membership_id' => $membership['id']]) as $link) {
            $role = $this->database->findOne('auth_roles', ['id' => $link['role_id']]);
            if ($role !== null) {
                $roles[] = ['value' => (string) $role['id'], 'display' => (string) $role['name'], '$ref' => $location . '/Groups/' . $role['id']];
            }
        }
        usort($roles, static fn(array $a, array $b): int => $a['value'] <=> $b['value']);
        $resource = [
            'schemas' => [self::SCHEMA],
            'id' => $user->id,
            'userName' => $user->email,
            'displayName' => $user->displayName,
            'name' => ['formatted' => $user->displayName],
            'emails' => [['value' => $user->email, 'primary' => true]],
            'active' => $user->status !== User::STATUS_DISABLED,
            'groups' => $roles,
            'meta' => ['resourceType' => Resource::USER, 'created' => $user->createdAt->format(DATE_ATOM), 'lastModified' => $user->updatedAt->format(DATE_ATOM), 'location' => $location . '/Users/' . $user->id],
        ];
        $externalId = $this->resources->externalId($connection, Resource::USER, $user->id);
        if ($externalId !== null) {
            $resource['externalId'] = $externalId;
        }

        return $resource;
    }

    /**
     * @param array<string, mixed> $resource
     * @return array<string, mixed>
     */
    public static function flat(array $resource): array
    {
        return [
            'id' => $resource['id'],
            'username' => $resource['userName'],
            'emails' => [$resource['userName']],
            'displayname' => $resource['displayName'] ?? '',
            'externalid' => $resource['externalId'] ?? '',
            'active' => ($resource['active'] ?? true) ? 'true' : 'false',
        ];
    }

    /**
     * @return array<string, mixed>|null
     */
    private function membership(Connection $connection, string $userId): ?array
    {
        return $this->database->findOne('auth_memberships', ['user_id' => $userId, 'organization_id' => $connection->organizationId]);
    }

    private function join(Connection $connection, User $user): void
    {
        if ($this->membership($connection, $user->id) !== null) {
            return;
        }
        $now = $this->clock->now();
        $membership = new Membership();
        $membership->id = Uuid::v7()->toRfc4122();
        $membership->userId = $user->id;
        $membership->organizationId = $connection->organizationId;
        $membership->status = Membership::STATUS_ACTIVE;
        $membership->joinedAt = $now;
        $membership->createdAt = $now;
        $membership->updatedAt = $now;
        $this->unitOfWork->persist($membership);
        $role = $this->database->findOne('auth_roles', ['organization_id' => $connection->organizationId, 'slug' => self::DEFAULT_ROLE]);
        if ($role !== null && is_string($role['id'] ?? null)) {
            $link = new MembershipRole();
            $link->membershipId = $membership->id;
            $link->roleId = $role['id'];
            $this->unitOfWork->persist($link);
        }
        $this->unitOfWork->flush();
        $this->resources->recordMembership($connection, $user->id);
        $this->events->dispatch(new MemberJoined($connection->organizationId, $user->id, $user->email));
    }

    private function setActive(Connection $connection, User $user, bool $active): void
    {
        if ($active && $user->status === User::STATUS_DISABLED) {
            $this->admin->enable(self::ACTOR, $user->id);
        } elseif (!$active && $user->status !== User::STATUS_DISABLED) {
            $this->admin->disable(self::ACTOR, $user->id);
        }
    }

    /**
     * @throws ScimError
     */
    private function rename(User $user, string $email): void
    {
        if ($email === $user->email) {
            return;
        }
        $taken = $this->users->findOneBy(['email' => $email]);
        if ($taken instanceof User && $taken->id !== $user->id) {
            throw ScimError::conflict('Another account uses this userName.');
        }
        $user->email = $email;
    }

    private function reload(string $id): User
    {
        $user = $this->users->find($id);

        return $user instanceof User ? $user : throw ScimError::notFound('User');
    }

    /**
     * @param array<string, mixed> $body
     * @throws ScimError
     */
    private static function email(array $body): string
    {
        $userName = $body['userName'] ?? null;
        if (!is_string($userName) || trim($userName) === '') {
            $emails = is_array($body['emails'] ?? null) ? $body['emails'] : [];
            foreach ($emails as $entry) {
                if (is_array($entry) && is_string($entry['value'] ?? null)) {
                    $userName = $entry['value'];
                    if (($entry['primary'] ?? false) === true) {
                        break;
                    }
                }
            }
        }

        return self::validEmail(is_string($userName) ? $userName : '');
    }

    /**
     * @throws ScimError
     */
    private static function validEmail(string $value): string
    {
        $email = EmailNormalizer::normalize($value);
        if ($email === '' || strlen($email) > 320 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw ScimError::invalid('userName must be the member\'s email address.');
        }

        return $email;
    }

    /**
     * @param array<string, mixed> $body
     */
    private static function displayName(array $body): ?string
    {
        $name = $body['displayName'] ?? null;
        if (!is_string($name) || trim($name) === '') {
            $parts = is_array($body['name'] ?? null) ? $body['name'] : [];
            $name = is_string($parts['formatted'] ?? null) && trim($parts['formatted']) !== '' ? $parts['formatted'] : trim((is_string($parts['givenName'] ?? null) ? $parts['givenName'] : '') . ' ' . (is_string($parts['familyName'] ?? null) ? $parts['familyName'] : ''));
        }
        $name = trim($name);

        return $name === '' ? null : (strlen($name) > 120 ? substr($name, 0, 120) : $name);
    }

    /**
     * @param array<string, mixed> $body
     */
    private static function externalId(array $body): ?string
    {
        $externalId = $body['externalId'] ?? null;

        return is_string($externalId) && trim($externalId) !== '' ? trim($externalId) : null;
    }
}
