<?php

declare(strict_types=1);

namespace Polaris\Messaging\Template;

/**
 * Renders a template key (`email.verify`, `sms.otp`) for a locale with the variables the sender has;
 * an organization's override wins over the instance's, which wins over the bundled strings.
 *
 * @throws TemplateNotFoundException
 */
interface TemplateRenderer
{
    /**
     * @param array<string, mixed> $vars
     */
    public function render(string $key, string $locale, array $vars, ?string $organizationId = null): Rendered;
}
