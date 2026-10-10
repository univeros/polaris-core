<?php

declare(strict_types=1);

namespace Polaris\OAuth\Model;

use DateTimeImmutable;

use const DATE_ATOM;

/**
 * A backchannel authentication request (`polaris_oauth_ciba_request`): a client asking a user, named
 * by their email, to approve a sign-in; the user decides from their own session, the client polls.
 */
final class CibaRequest
{
    public const string STATUS_PENDING = 'pending';
    public const string STATUS_APPROVED = 'approved';
    public const string STATUS_DENIED = 'denied';
    public const string STATUS_USED = 'used';

    public string $id = '';
    public string $clientId = '';
    public string $userId = '';
    public ?string $organizationId = null;
    /** @var list<string> */
    public array $scopes = [];
    public ?string $bindingMessage = null;
    public ?string $resource = null;
    public string $status = self::STATUS_PENDING;
    public ?int $authTime = null;
    public ?DateTimeImmutable $lastPolledAt = null;
    public DateTimeImmutable $expiresAt;
    public DateTimeImmutable $createdAt;

    /**
     * What the user sees before deciding.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'client_id' => $this->clientId,
            'scopes' => $this->scopes,
            'binding_message' => $this->bindingMessage,
            'status' => $this->status,
            'expires_at' => $this->expiresAt->format(DATE_ATOM),
            'created_at' => $this->createdAt->format(DATE_ATOM),
        ];
    }
}
