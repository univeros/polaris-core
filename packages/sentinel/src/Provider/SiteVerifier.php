<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

use Override;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use SensitiveParameter;

use function http_build_query;
use function is_array;
use function json_decode;

/**
 * The `siteverify` protocol Turnstile and hCaptcha share: a form POST with the secret, the token and
 * the client IP, a JSON `success`. A transport failure is a failed verification.
 */
abstract class SiteVerifier implements BotVerifier
{
    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
        #[SensitiveParameter] private readonly string $secret,
    ) {
    }

    abstract protected function endpoint(): string;

    #[Override]
    public function verify(string $token, ?string $ip): bool
    {
        $form = ['secret' => $this->secret, 'response' => $token];
        if ($ip !== null) {
            $form['remoteip'] = $ip;
        }
        $request = $this->requests->createRequest('POST', $this->endpoint())
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->streams->createStream(http_build_query($form)));
        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface) {
            return false;
        }
        $body = json_decode((string) $response->getBody(), true);

        return $response->getStatusCode() === 200 && is_array($body) && ($body['success'] ?? false) === true;
    }
}
