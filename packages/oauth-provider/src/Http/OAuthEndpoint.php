<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\ClientCredentials;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Discovery;
use Polaris\OAuth\Dpop;
use Polaris\OAuth\Model\Client;
use Polaris\OAuth\OAuthException;
use Polaris\OAuth\Settings;

use function is_string;
use function preg_split;
use function str_replace;
use function trim;
use function ucwords;

/**
 * What every OAuth route shares: the RFC 6749 error document (an RFC 9457 problem whose `error` is the
 * RFC code, with `error_description`), the client's credentials and DPoP proof read from what the
 * request middleware handed over, and the `no-store` headers of a token response.
 */
abstract class OAuthEndpoint extends Endpoint
{
    protected const array NO_STORE = ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache'];

    /**
     * @param array<string, string> $headers
     */
    protected function refuse(OAuthException $exception, array $headers = []): Result
    {
        $body = [
            'type' => self::PROBLEM_TYPES . 'oauth/' . $exception->error,
            'title' => ucwords(str_replace('_', ' ', $exception->error)),
            'status' => $exception->status,
            'detail' => $exception->description,
            'error' => $exception->error,
            'error_description' => $exception->description,
            'message' => $exception->description,
        ];
        if ($exception->error === OAuthException::INVALID_CLIENT && $exception->status === 401) {
            $headers['WWW-Authenticate'] = 'Basic realm="oauth"';
        }

        return new Result($exception->status, $body, [...self::NO_STORE, ...$headers], problem: true);
    }

    protected function credentials(Input $input): ClientCredentials
    {
        $authorization = $input->attribute(OAuthRequestMiddleware::AUTHORIZATION);

        return ClientCredentials::from($input->all(), is_string($authorization) ? $authorization : null);
    }

    /**
     * The client the request authenticates as, for `$path` (the audience of a signed assertion).
     *
     * @throws OAuthException
     */
    protected function authenticatedClient(Clients $clients, Discovery $discovery, Input $input, string $path): Client
    {
        return $clients->authenticate($this->credentials($input), $discovery->url($path), $discovery->issuer());
    }

    /**
     * The thumbprint of the DPoP key the request proved, null without a proof; a client registered for
     * DPoP-bound tokens, or a server requiring DPoP, must prove one.
     *
     * @throws OAuthException `invalid_dpop_proof`
     */
    protected function proof(Dpop $dpop, Settings $settings, Input $input, ?Client $client, ?string $accessToken = null): ?string
    {
        if ($settings->dpop === Settings::DPOP_OFF) {
            return null;
        }
        $header = $input->attribute(OAuthRequestMiddleware::DPOP);
        $method = $input->attribute(OAuthRequestMiddleware::METHOD);
        $url = $input->attribute(OAuthRequestMiddleware::URL);
        $jkt = $dpop->verify(is_string($header) ? $header : null, is_string($method) ? $method : 'POST', is_string($url) ? $url : '', $accessToken);
        if ($jkt === null && ($settings->dpop === Settings::DPOP_REQUIRED || ($client !== null && $client->dpopBound))) {
            throw new OAuthException(OAuthException::INVALID_DPOP_PROOF, 'A DPoP proof is required.');
        }

        return $jkt;
    }

    /**
     * @param array<string, mixed> $body
     */
    protected function tokenResponse(array $body, int $status = 200): Result
    {
        return new Result($status, $body, self::NO_STORE);
    }

    protected static function text(Input $input, string $field): ?string
    {
        $value = $input->get($field);

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    /**
     * @return list<string>|null
     */
    protected static function words(Input $input, string $field): ?array
    {
        $value = self::text($input, $field);

        return $value === null ? null : (preg_split('/\s+/', $value) ?: []);
    }
}
