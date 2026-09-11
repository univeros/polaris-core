<?php

declare(strict_types=1);

namespace Polaris\Messaging\Channel;

use Override;
use Polaris\Messaging\Channel;
use Polaris\Messaging\DeliveryException;
use Polaris\Messaging\Message;
use Polaris\Messaging\Receipt;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;

use function sprintf;

/**
 * What the SMS providers share: one HTTP request per message through a PSR-18 client, a 2xx is a
 * delivery, anything else a {@see DeliveryException} carrying the status.
 */
abstract class HttpSmsChannel implements Channel
{
    public function __construct(
        protected readonly ClientInterface $client,
        protected readonly RequestFactoryInterface $requests,
        protected readonly StreamFactoryInterface $streams,
        protected readonly ClockInterface $clock,
    ) {
    }

    #[Override]
    public function supports(string $kind): bool
    {
        return $kind === Message::SMS;
    }

    #[Override]
    public function send(Message $message): Receipt
    {
        try {
            $response = $this->client->sendRequest($this->request($message));
        } catch (ClientExceptionInterface $exception) {
            throw new DeliveryException($exception->getMessage(), 0, $exception);
        }
        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new DeliveryException(sprintf('%s answered HTTP %d.', $this->name(), $status));
        }

        return new Receipt($this->name(), $this->providerId($response), $this->clock->now());
    }

    abstract protected function request(Message $message): RequestInterface;

    abstract protected function providerId(ResponseInterface $response): ?string;

    /**
     * @return array<string, mixed>
     */
    protected static function json(ResponseInterface $response): array
    {
        $decoded = json_decode((string) $response->getBody(), true);

        return is_array($decoded) ? $decoded : [];
    }
}
