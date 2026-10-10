<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Devices;
use Polaris\OAuth\Discovery;
use Polaris\OAuth\OAuthException;
use Polaris\OAuth\Scopes;

use function preg_match;

/**
 * `POST /oauth2/device/code` (RFC 8628 §3.1): a device asks for its codes.
 */
final class DeviceCodeEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Clients $clients, private readonly Devices $devices, private readonly Scopes $scopes, private readonly Discovery $discovery)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        try {
            $client = $this->authenticatedClient($this->clients, $this->discovery, $input, '/oauth2/device/code');
            $resource = self::text($input, 'resource');
            if ($resource !== null && preg_match('~^https?://[^\s#]+$~', $resource) !== 1) {
                throw new OAuthException(OAuthException::INVALID_TARGET, 'resource must be an absolute URI.');
            }
            $response = $this->devices->start($client, $this->scopes->parse(self::text($input, 'scope'), $client), $resource);
        } catch (OAuthException $exception) {
            return $this->refuse($exception);
        }

        return $this->tokenResponse($response);
    }
}
