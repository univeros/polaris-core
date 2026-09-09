<?php

declare(strict_types=1);

namespace Polaris\Exception;

/**
 * A token string is malformed, unsigned, expired, or otherwise fails verification.
 */
class InvalidTokenException extends AuthorizationTokenException
{
}
