<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use function is_string;

/**
 * A validated authorization request waiting for the user's decision, kept in the cache under its
 * id for ten minutes: what the consent page shows and what the code is minted from.
 */
final readonly class PendingRequest
{
    /**
     * @param list<string> $scopes
     */
    public function __construct(
        public string $id,
        public string $clientId,
        public string $redirectUri,
        public array $scopes,
        public ?string $state,
        public string $codeChallenge,
        public ?string $nonce,
        public ?string $resource,
        public ?string $dpopJkt,
        public ?string $prompt,
        public int $createdAt,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scopes' => $this->scopes,
            'state' => $this->state,
            'code_challenge' => $this->codeChallenge,
            'nonce' => $this->nonce,
            'resource' => $this->resource,
            'dpop_jkt' => $this->dpopJkt,
            'prompt' => $this->prompt,
            'created_at' => $this->createdAt,
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $scopes = [];
        foreach ((array) ($data['scopes'] ?? []) as $scope) {
            if (is_string($scope)) {
                $scopes[] = $scope;
            }
        }

        return new self(
            (string) $data['id'],
            (string) $data['client_id'],
            (string) $data['redirect_uri'],
            $scopes,
            is_string($data['state'] ?? null) ? $data['state'] : null,
            (string) $data['code_challenge'],
            is_string($data['nonce'] ?? null) ? $data['nonce'] : null,
            is_string($data['resource'] ?? null) ? $data['resource'] : null,
            is_string($data['dpop_jkt'] ?? null) ? $data['dpop_jkt'] : null,
            is_string($data['prompt'] ?? null) ? $data['prompt'] : null,
            (int) ($data['created_at'] ?? 0),
        );
    }
}
