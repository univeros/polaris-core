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

use function base64_encode;
use function http_build_query;
use function is_string;
use function sprintf;

/**
 * SMS through Twilio's Messages API (`POST /2010-04-01/Accounts/{sid}/Messages.json`, basic auth).
 */
final class TwilioSmsChannel extends HttpSmsChannel
{
    public function __construct(
        ClientInterface $client,
        RequestFactoryInterface $requests,
        StreamFactoryInterface $streams,
        ClockInterface $clock,
        private readonly string $accountSid,
        #[SensitiveParameter] private readonly string $authToken,
        private readonly string $from,
        private readonly string $baseUrl = 'https://api.twilio.com',
    ) {
        parent::__construct($client, $requests, $streams, $clock);
    }

    #[Override]
    public function name(): string
    {
        return 'twilio';
    }

    #[Override]
    protected function request(Message $message): RequestInterface
    {
        return $this->requests->createRequest('POST', sprintf('%s/2010-04-01/Accounts/%s/Messages.json', $this->baseUrl, $this->accountSid))
            ->withHeader('Authorization', 'Basic ' . base64_encode($this->accountSid . ':' . $this->authToken))
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->streams->createStream(http_build_query(['To' => $message->to, 'From' => $this->from, 'Body' => $message->text])));
    }

    #[Override]
    protected function providerId(ResponseInterface $response): ?string
    {
        $sid = self::json($response)['sid'] ?? null;

        return is_string($sid) ? $sid : null;
    }
}
