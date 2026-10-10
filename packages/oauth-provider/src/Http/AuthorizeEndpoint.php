<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\Authorization;
use Polaris\OAuth\OAuthException;
use Polaris\OAuth\Scopes;
use Polaris\OAuth\Settings;

use function is_string;
use function str_contains;

/**
 * `GET /oauth2/authorize`: validates the request and parks it; a browser is sent to the host's
 * consent page with `?request=<id>`, an XHR client (`Accept: application/json`) gets the request's
 * data as JSON; `?request=<id>` alone answers the data of a parked request (what the consent page
 * loads). Errors the client caused before a redirect URI is trusted are answered here; the rest go
 * to the redirect URI as RFC 6749 §4.1.2.1 says.
 */
final class AuthorizeEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Authorization $authorization, private readonly Scopes $scopes, private readonly Settings $settings)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $accept = $input->attribute(OAuthRequestMiddleware::ACCEPT);
        $json = $this->settings->consentUrl === null || (is_string($accept) && str_contains($accept, 'application/json'));
        try {
            if (self::text($input, 'request') !== null) {
                [$request, $client] = $this->authorization->pending(self::text($input, 'request'));
            } else {
                [$request, $client] = $this->authorization->start($input->all());
            }
        } catch (OAuthException $exception) {
            return $this->refuse($exception);
        }
        if (!$json && self::text($input, 'request') === null) {
            return new Result(302, [], ['Location' => Authorization::redirect((string) $this->settings->consentUrl, ['request' => $request->id]), ...self::NO_STORE]);
        }
        $descriptions = $this->scopes->all();
        $scopes = [];
        foreach ($request->scopes as $scope) {
            $scopes[] = ['name' => $scope, 'description' => $descriptions[$scope] ?? $scope];
        }

        return new Result(200, ['data' => [
            'request' => $request->id,
            'client' => $client->toPublicArray(),
            'scopes' => $scopes,
            'redirect_uri' => $request->redirectUri,
            'state' => $request->state,
            'prompt' => $request->prompt,
            'decision_endpoint' => '/oauth2/authorize/decision',
        ]], self::NO_STORE);
    }
}
