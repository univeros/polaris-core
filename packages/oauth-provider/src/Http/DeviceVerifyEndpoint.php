<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Devices;
use Polaris\OAuth\OAuthException;
use Polaris\OAuth\Scopes;

use const DATE_ATOM;

/**
 * `GET /oauth2/device/verify?user_code=`: what the host's device page shows a signed-in user before
 * they decide: the client and the scopes behind the code they typed.
 */
final class DeviceVerifyEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Devices $devices, private readonly Clients $clients, private readonly Scopes $scopes)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        if ($this->token($input) === null) {
            return $this->unauthorized();
        }
        try {
            $device = $this->devices->byUserCode(self::text($input, 'user_code') ?? '');
            $client = $this->clients->find($device->clientId);
            if ($client === null) {
                throw new OAuthException(OAuthException::INVALID_CLIENT, 'Unknown client.', 400);
            }
        } catch (OAuthException $exception) {
            return $this->refuse($exception);
        }
        $descriptions = $this->scopes->all();
        $scopes = [];
        foreach ($device->scopes as $scope) {
            $scopes[] = ['name' => $scope, 'description' => $descriptions[$scope] ?? $scope];
        }

        return new Result(200, ['data' => ['user_code' => $device->userCode, 'client' => $client->toPublicArray(), 'scopes' => $scopes, 'expires_at' => $device->expiresAt->format(DATE_ATOM)]], self::NO_STORE);
    }
}
