<?php

declare(strict_types=1);

namespace Polaris\Tests\Support\Plugin;

use DateTimeImmutable;

/**
 * The sample plugin's one model.
 */
final class SampleNote
{
    public string $id = '';
    public string $text = '';
    public DateTimeImmutable $createdAt;
}
