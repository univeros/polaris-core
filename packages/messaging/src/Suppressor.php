<?php

declare(strict_types=1);

namespace Polaris\Messaging;

/**
 * Quiet mode: a package that judges abuse (`polaris/sentinel`) says whether a non-essential message to
 * a recipient should be dropped. Essential messages (a verification, a reset) always go.
 */
interface Suppressor
{
    public function suppresses(Message $message): bool;
}
