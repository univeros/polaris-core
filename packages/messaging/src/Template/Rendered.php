<?php

declare(strict_types=1);

namespace Polaris\Messaging\Template;

/**
 * A template rendered for one recipient: the subject (email only), the text, the HTML when the template has one.
 */
final readonly class Rendered
{
    public function __construct(public string $text, public ?string $subject = null, public ?string $html = null)
    {
    }
}
