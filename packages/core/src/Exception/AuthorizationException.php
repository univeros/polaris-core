<?php

declare(strict_types=1);

namespace Polaris\Exception;

use RuntimeException;

/**
 * Thrown by the {@see \Polaris\Authorization\Gate} when a caller lacks a required
 * permission for a programmatic (in-domain) check. Endpoints map it to `403 forbidden`.
 */
final class AuthorizationException extends RuntimeException
{
}
