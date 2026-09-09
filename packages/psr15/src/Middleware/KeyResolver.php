<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Polaris\Contract\TokenInterface;
use Polaris\Http\Attributes;
use Psr\Http\Message\ServerRequestInterface;

use function is_string;

/**
 * Rate-limit keys: the client IP, or the token subject when a token is present.
 */
final class KeyResolver
{
    public static function ip(ServerRequestInterface $request): string
    {
        $attribute = $request->getAttribute(Attributes::IP_ADDRESS);
        if (is_string($attribute) && $attribute !== '') {
            return $attribute;
        }
        $remote = $request->getServerParams()['REMOTE_ADDR'] ?? null;

        return is_string($remote) && $remote !== '' ? $remote : 'unknown';
    }

    public static function subject(ServerRequestInterface $request): string
    {
        $token = $request->getAttribute(Attributes::TOKEN);
        if ($token instanceof TokenInterface) {
            $subject = $token->getMetadata('sub');
            if (is_string($subject) && $subject !== '') {
                return 'user:' . $subject;
            }
        }

        return self::ip($request);
    }
}
