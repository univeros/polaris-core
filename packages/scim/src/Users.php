<?php

declare(strict_types=1);

namespace Polaris\Scim;

use DateTimeImmutable;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Event\MemberJoined;
use Polaris\Event\MemberStatusChanged;
use Polaris\Identity\EmailNormalizer;
use Polaris\Identity\SessionService;
use Polaris\Identity\UserAdminService;
use Polaris\Model\Membership;
use Polaris\Model\MembershipRole;
use Polaris\Model\RefreshToken;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\Model\Resource;
use Polaris\Sso\Domains;
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
use function strrchr;
use function substr;
use function trim;
use function usort;

use const DATE_ATOM;
use const FILTER_VALIDATE_EMAIL;

/**
 * SCIM Users onto Polaris users who are members of the connection's organization: `userName` and the
 * primary email are the email, `displayName`/`name.formatted` the display name, `active` the account
 * status and the membership's, `externalId` the directory's own id. A created user is verified and has
 * no password.
 *
 * An account is global, a directory belongs to one organization: the connection changes an account's
 * email, name and status only when it owns it (it created the account, which belongs to no other
 * organization). An existing account joins only when its email's domain is verified for the
 * organization (polaris/sso), with its profile untouched; `active: false` suspends the membership, and
 * deprovisioning anonymises (or deactivates) an owned account and removes any other's membership.
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
        private readonly SessionService $sessions,
        private readonly Owners $owners,
        private readonly ?Domains $domains = null,
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
        $user = $this->users->findOneBy(['email' => $email]);
        if ($user instanceof User) {
            if ($this->membership($connection, $user->id) !== null) {
                throw ScimError::conflict('A member with this userName exists.');
            }
            if (!$this->mayLink($connection, $email)) {
                throw ScimError::conflict('Another account uses this userName.');
            }
            $this->join($connection, $user, null);
        } else {
            $now = $this->clock->now();
            $user = new User();
            $user->id = Uuid::v7()->toRfc4122();
            $user->email = $email;
            $user->emailVerifiedAt = $now;
            $user->displayName = self::displayName($body);
            $user->createdAt = $now;
            $user->updatedAt = $now;
            $this->unitOfWork->persist($user);
            $this->unitOfWork->flush();
            $this->join($connection, $user, $now);
        }
        $this->resources->setExternalId($connection, Resource::USER, $user->id, self::externalId($body));
        if (($body['active'] ?? true) === false) {
            $this->setActive($connection, $user, false);
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
        return $this->write($connection, $user, [
            'email' => self::email($body),
            'name' => [self::displayName($body)],
            'externalId' => [self::externalId($body)],
            'active' => ($body['active'] ?? true) !== false,
        ]);
    }

    /**
     * PATCH: the operations touch `active`, `userName`, `displayName`, `name.*` and `externalId`.
     *
     * @param list<array{string, string|null, mixed}> $operations
     * @throws ScimError
     */
    public function patch(Connection $connection, User $user, array $operations): User
    {
        $change = [];
        foreach ($operations as $operation) {
            $active = Patch::scalar($operation, 'active');
            if ($active !== null) {
                $change['active'] = filter_var($active, FILTER_VALIDATE_BOOLEAN);
            }
            $userName = Patch::scalar($operation, 'userName');
            if (is_string($userName)) {
                $change['email'] = self::validEmail($userName);
            }
            foreach (['displayName', 'name.formatted'] as $attribute) {
                $name = Patch::scalar($operation, $attribute);
                if ($name !== null) {
                    $change['name'] = [is_string($name) && trim($name) !== '' ? trim($name) : null];
                }
            }
            $given = Patch::scalar($operation, 'name.givenName');
            $family = Patch::scalar($operation, 'name.familyName');
            if (is_string($given) || is_string($family)) {
                $change['name'] = [trim((is_string($given) ? $given : '') . ' ' . (is_string($family) ? $family : ''))];
            }
            $externalId = Patch::scalar($operation, 'externalId');
            if ($externalId !== null || ($operation[0] === 'remove' && $operation[1] !== null && Patch::stripUrn($operation[1]) === 'externalId')) {
                $change['externalId'] = [is_string($externalId) ? $externalId : null];
            }
        }

        return $this->write($connection, $user, $change);
    }

    /**
     * DELETE: an account the connection owns is anonymised or deactivated, as its `deprovision` says (its
     * membership removed); any other account only leaves the organization: its membership is suspended
     * (the organization's sessions end) and removed. Never the organization's last active owner.
     *
     * @return string `deactivated` or `deleted`
     * @throws ScimError
     */
    public function delete(Connection $connection, User $user): string
    {
        $outcome = $connection->deprovision() === Connection::DELETE ? 'deleted' : 'deactivated';
        if (!$this->owns($connection, $user)) {
            $this->setActive($connection, $user, false);
            $this->leave($connection, $user->id);

            return $outcome;
        }
        if ($outcome === 'deleted') {
            $this->admin->anonymize(self::ACTOR, $user->id);
            $this->resources->forget($connection, Resource::USER, $user->id);
            $this->resources->forgetMembership($connection, $user->id);

            return $outcome;
        }
        $this->leave($connection, $user->id);
        $this->admin->disable(self::ACTOR, $user->id);

        return $outcome;
    }

    /**
     * What the directory sees as `active`: an enabled account whose membership is active.
     */
    public function active(Connection $connection, User $user): bool
    {
        return $user->status !== User::STATUS_DISABLED && ($this->membership($connection, $user->id)['status'] ?? null) === Membership::STATUS_ACTIVE;
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
            'active' => $this->active($connection, $user),
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

    /**
     * `$created` is the user's creation time when the connection created the user too.
     */
    private function join(Connection $connection, User $user, ?DateTimeImmutable $created): void
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
        $this->resources->recordMembership($connection, $user->id, $created);
        $this->events->dispatch(new MemberJoined($connection->organizationId, $user->id, $user->email));
    }

    /**
     * PUT and PATCH: `email`, `name` ([?string]), `externalId` ([?string]) and `active` when present. The
     * email and the name of an account the connection does not own are the user's own.
     *
     * @param array{email?: string, name?: array{?string}, externalId?: array{?string}, active?: bool} $change
     * @throws ScimError
     */
    private function write(Connection $connection, User $user, array $change): User
    {
        $owned = $this->owns($connection, $user);
        $email = $change['email'] ?? $user->email;
        if (!$owned && $email !== $user->email) {
            throw new ScimError(403, 'userName is managed by the account\'s owner, not by this directory.', ScimError::MUTABILITY);
        }
        if ($owned) {
            $taken = $email === $user->email ? null : $this->users->findOneBy(['email' => $email]);
            if ($taken instanceof User && $taken->id !== $user->id) {
                throw ScimError::conflict('Another account uses this userName.');
            }
            $user->email = $email;
            $user->displayName = isset($change['name']) ? $change['name'][0] : $user->displayName;
            $user->updatedAt = $this->clock->now();
            $this->unitOfWork->persist($user);
            $this->unitOfWork->flush();
        }
        if (isset($change['externalId'])) {
            $this->resources->setExternalId($connection, Resource::USER, $user->id, $change['externalId'][0]);
        }
        if (isset($change['active'])) {
            $this->setActive($connection, $user, $change['active']);
        }

        return $this->reload($user->id);
    }

    /**
     * Whether the connection owns the account: it created it, and the account is a member of no other
     * organization.
     */
    private function owns(Connection $connection, User $user): bool
    {
        if (!$this->resources->createdUser($connection, $user->id, $user->createdAt)) {
            return false;
        }
        foreach ($this->database->findMany('auth_memberships', ['user_id' => $user->id]) as $membership) {
            if ($membership['organization_id'] !== $connection->organizationId) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether an existing account with this email may join: its domain is verified for the organization.
     */
    private function mayLink(Connection $connection, string $email): bool
    {
        $at = strrchr($email, '@');

        return $this->domains !== null && $at !== false && $this->domains->verifiedFor($connection->organizationId, substr($at, 1));
    }

    /**
     * Suspends or reactivates the membership (suspension ends the organization's sessions, never of its
     * last active owner); an owned account that is disabled is enabled again.
     *
     * @throws ScimError
     */
    private function setActive(Connection $connection, User $user, bool $active): void
    {
        $membership = $this->membership($connection, $user->id);
        $status = $active ? Membership::STATUS_ACTIVE : Membership::STATUS_SUSPENDED;
        if ($membership !== null && $membership['status'] !== $status) {
            $this->owners->keep($connection, fn(): int => $this->database->update('auth_memberships', ['id' => $membership['id']], ['status' => $status, 'updated_at' => $this->clock->now()]));
            $this->events->dispatch(new MemberStatusChanged($connection->organizationId, $user->id, $status, self::ACTOR));
        }
        if (!$active) {
            $this->sessions->revokeAllForOrganization($user->id, $connection->organizationId, RefreshToken::REASON_ADMIN);
        } elseif ($user->status === User::STATUS_DISABLED && $this->owns($connection, $user)) {
            $this->admin->enable(self::ACTOR, $user->id);
        }
    }

    /**
     * Removes the membership (with its roles) and what the connection remembers of the user, never the
     * organization's last active owner.
     *
     * @throws ScimError
     */
    private function leave(Connection $connection, string $userId): void
    {
        $this->owners->keep($connection, function () use ($connection, $userId): void {
            $membership = $this->membership($connection, $userId);
            if ($membership !== null) {
                $this->database->delete('auth_membership_roles', ['membership_id' => $membership['id']]);
                $this->database->delete('auth_memberships', ['id' => $membership['id']]);
            }
            $this->resources->forgetMembership($connection, $userId);
            $this->resources->forget($connection, Resource::USER, $userId);
        });
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
