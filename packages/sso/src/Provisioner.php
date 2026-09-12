<?php

declare(strict_types=1);

namespace Polaris\Sso;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Event\MemberJoined;
use Polaris\Identity\EmailNormalizer;
use Polaris\Model\Membership;
use Polaris\Model\MembershipRole;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Sso\Model\Provider;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

use function is_string;

/**
 * The user behind an identity and their membership in the provider's organization: found by email, or
 * created when the provider provisions just in time (the IdP vouched for the mailbox, so the email is
 * verified); the membership is created with the provider's default roles and `MemberJoined` is emitted.
 */
final class Provisioner
{
    public const string DEFAULT_ROLE = 'member';

    public function __construct(
        private readonly UserRepository $users,
        private readonly DatabaseAdapter $database,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly EventDispatcherInterface $events,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @return array{User, bool} the user and whether they were just created
     * @throws SsoException when the user is unknown and the provider does not provision, or is disabled
     */
    public function resolve(Provider $provider, Identity $identity): array
    {
        $email = EmailNormalizer::normalize($identity->email);
        $user = $this->users->findOneBy(['email' => $email]);
        if ($user instanceof User) {
            if ($user->status === User::STATUS_DISABLED) {
                throw new SsoException(SsoException::ACCOUNT_DISABLED, 'the account is disabled');
            }

            return [$user, false];
        }
        if (!$provider->jitEnabled()) {
            throw new SsoException(SsoException::USER_UNKNOWN, 'no account for ' . $email . ' and the provider does not provision');
        }
        $now = $this->clock->now();
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = $email;
        $user->displayName = $identity->name;
        $user->emailVerifiedAt = $now;
        $user->createdAt = $now;
        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();

        return [$user, true];
    }

    /**
     * @return bool whether a membership was created
     * @throws SsoException when the membership is suspended
     */
    public function ensureMembership(Provider $provider, User $user): bool
    {
        $existing = $this->database->findOne('auth_memberships', ['user_id' => $user->id, 'organization_id' => $provider->organizationId]);
        if ($existing !== null) {
            if (($existing['status'] ?? null) === Membership::STATUS_SUSPENDED) {
                throw new SsoException(SsoException::MEMBERSHIP_SUSPENDED, 'the membership is suspended');
            }

            return false;
        }
        $now = $this->clock->now();
        $membership = new Membership();
        $membership->id = Uuid::v7()->toRfc4122();
        $membership->userId = $user->id;
        $membership->organizationId = $provider->organizationId;
        $membership->status = Membership::STATUS_ACTIVE;
        $membership->joinedAt = $now;
        $membership->createdAt = $now;
        $membership->updatedAt = $now;
        $this->unitOfWork->persist($membership);
        $slugs = $provider->jitRoles();
        foreach ($slugs === [] ? [self::DEFAULT_ROLE] : $slugs as $slug) {
            $role = $this->database->findOne('auth_roles', ['organization_id' => $provider->organizationId, 'slug' => $slug]);
            if ($role === null || !is_string($role['id'] ?? null)) {
                continue;
            }
            $link = new MembershipRole();
            $link->membershipId = $membership->id;
            $link->roleId = $role['id'];
            $this->unitOfWork->persist($link);
        }
        $this->unitOfWork->flush();
        $this->events->dispatch(new MemberJoined($provider->organizationId, $user->id, $user->email));

        return true;
    }
}
