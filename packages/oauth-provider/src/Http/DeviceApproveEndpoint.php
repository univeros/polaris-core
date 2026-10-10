<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Devices;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\OAuth\OAuthException;
use Psr\EventDispatcher\EventDispatcherInterface;

use function is_int;

/**
 * `POST /oauth2/device/approve`: the signed-in user approves (`approve: true`) or refuses the device
 * behind a user code; the device learns it at its next poll.
 */
final class DeviceApproveEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Devices $devices, private readonly EventDispatcherInterface $events)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $approve = $input->get('approve') === true;
        try {
            $device = $this->devices->byUserCode(self::text($input, 'user_code') ?? '');
            $authTime = $token->getMetadata('auth_time');
            $this->devices->decide($device, $approve, $this->actorId($token), $this->actorOrg($token), is_int($authTime) ? $authTime : null);
        } catch (OAuthException $exception) {
            return $this->refuse($exception);
        }
        $context = $this->client($input);
        $this->events->dispatch(new OAuthEvent(AuditNames::DEVICE_DECIDED, $this->actorId($token), $device->clientId, $this->actorOrg($token), ['approved' => $approve, 'scopes' => $device->scopes], $context->ip, $context->userAgent));

        return new Result(200, ['data' => ['status' => $approve ? 'approved' : 'denied']], self::NO_STORE);
    }
}
