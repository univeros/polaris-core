<?php

declare(strict_types=1);

namespace Polaris\Messaging\Model;

use DateTimeImmutable;

/**
 * An organization's override of one template in one locale (`polaris_messaging_template`).
 */
final class Template
{
    public string $id = '';
    public string $organizationId = '';
    public string $key = '';
    public string $locale = 'en';
    public ?string $subject = null;
    public string $text = '';
    public ?string $html = null;
    public DateTimeImmutable $updatedAt;
}
