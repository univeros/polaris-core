<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Http\Base\Payload;
use Altair\Http\Collection\InputCollection;
use Altair\Http\Contracts\DomainInterface;
use Altair\Http\Contracts\MiddlewareInterface;
use Altair\Http\Contracts\PayloadInterface;
use Altair\Http\Contracts\TokenInterface as AltairToken;
use Override;
use Polaris\Authorization\ResolvedAuthority;
use Polaris\Http\Attributes;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Univeros\Polaris\Http\Middleware\ClientContextMiddleware;
use Polaris\Http\MfaTicket;

use function str_ends_with;
use function strlen;
use function substr;

/**
 * Univeros glue (gone in WP7): serves a Polaris {@see Endpoint} as a framework domain. The
 * framework's input collection is split into the endpoint's data and the attributes its
 * middleware stored under the framework's names.
 */
final class AltairEndpointBridge implements DomainInterface
{
    private const string SUFFIX = '@altair';

    private const array ATTRIBUTES = [
        AltairToken::TOKEN_KEY => Attributes::TOKEN,
        MiddlewareInterface::ATTRIBUTE_IP_ADDRESS => Attributes::IP_ADDRESS,
        ClientContextMiddleware::ATTRIBUTE_USER_AGENT => Attributes::USER_AGENT,
        MfaTicket::ATTRIBUTE => Attributes::MFA_TICKET,
        ResolvedAuthority::class => Attributes::AUTHORITY,
    ];

    public function __construct(private readonly Endpoint $endpoint)
    {
    }

    /**
     * The container id the route table uses for an endpoint's bridge.
     */
    public static function id(string $endpointClass): string
    {
        return $endpointClass . self::SUFFIX;
    }

    /**
     * The endpoint class behind a bridge id (or the id itself when it is not a bridge id).
     */
    public static function endpointClass(string $id): string
    {
        return str_ends_with($id, self::SUFFIX) ? substr($id, 0, -strlen(self::SUFFIX)) : $id;
    }

    #[Override]
    public function __invoke(InputCollection $input): PayloadInterface
    {
        $data = [];
        $attributes = [];
        foreach ($input as $key => $value) {
            if (isset(self::ATTRIBUTES[$key])) {
                $attributes[self::ATTRIBUTES[$key]] = $value;
            } else {
                $data[$key] = $value;
            }
        }

        $result = ($this->endpoint)(new Input($data, $attributes));

        return (new Payload())->withStatus($result->status)->withOutput($result->body);
    }
}
