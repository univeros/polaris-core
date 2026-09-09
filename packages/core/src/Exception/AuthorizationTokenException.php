<?php

declare(strict_types=1);

namespace Polaris\Exception;

use RuntimeException;

/**
 * A token could not be issued or used for the requested authorization.
 */
class AuthorizationTokenException extends RuntimeException
{
}
