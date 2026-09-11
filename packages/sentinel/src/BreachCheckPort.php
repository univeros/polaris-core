<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use Override;
use Polaris\Contract\BreachedPasswordCheckInterface;
use Polaris\Sentinel\Provider\BreachChecker;
use SensitiveParameter;

/**
 * The plugin's breach checker as core's password-policy port (`auth.password.breach_check`), through
 * the port rule: the configuration's checker wins when set.
 */
final class BreachCheckPort implements BreachedPasswordCheckInterface
{
    public function __construct(private readonly BreachChecker $checker)
    {
    }

    #[Override]
    public function isBreached(#[SensitiveParameter] string $password): bool
    {
        return $this->checker->isBreached($password);
    }
}
