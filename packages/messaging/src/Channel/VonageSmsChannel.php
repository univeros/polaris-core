<?php

declare(strict_types=1);

namespace Polaris\Messaging\Channel;

use Override;
use Polaris\Messaging\Message;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use SensitiveParameter;

use function is_string;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * SMS through Vonage's SMS API (`POST https://rest.nexmo.com/sms/json`).
 */
final class VonageSmsChannel extends HttpSmsChannel
{
    public function __construct(
        ClientInterface $client,
        RequestFactoryInterface $requests,
        StreamFactoryInterface $streams,
        ClockInterface $clock,
        private readonly string $apiKey,
        #[SensitiveParameter] private readonly string $apiSecret,
        private readonly string $from,
        private readonly string $endpoint = 'https://rest.nexmo.com/sms/json',
    ) {
        parent::__construct($client, $requests, $streams, $clock);
    }

    #[Override]
    public function name(): string
    {
        return 'vonage';
    }

    #[Override]
    protected function request(Message $message): RequestInterface
    {
        $body = ['api_key' => $this->apiKey, 'api_secret' => $this->apiSecret, 'from' => $this->from, 'to' => $message->to, 'text' => $message->text];

        return $this->requests->createRequest('POST', $this->endpoint)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streams->createStream(json_encode($body, JSON_THROW_ON_ERROR)));
    }

    #[Override]
    protected function providerId(ResponseInterface $response): ?string
    {
        $id = self::json($response)['messages'][0]['message-id'] ?? null;

        return is_string($id) ? $id : null;
    }
}
