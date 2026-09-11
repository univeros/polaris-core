<?php

declare(strict_types=1);

namespace Polaris\Messaging\Template;

use Override;

use function htmlspecialchars;
use function is_scalar;
use function sprintf;
use function strtr;

use const ENT_QUOTES;

/**
 * Subject, text and HTML are strings with `{placeholders}`: an override's, or the translator's for the
 * locale (falling back to the default locale), the placeholders substituted (escaped in the HTML).
 */
final class PhpTemplateRenderer implements TemplateRenderer
{
    public function __construct(private readonly Translator $translator, private readonly Templates $templates, private readonly string $defaultLocale = 'en')
    {
    }

    #[Override]
    public function render(string $key, string $locale, array $vars, ?string $organizationId = null): Rendered
    {
        $parts = $this->templates->override($key, $locale, $organizationId)
            ?? $this->templates->override($key, $this->defaultLocale, $organizationId)
            ?? $this->bundled($key, $locale)
            ?? $this->bundled($key, $this->defaultLocale)
            ?? throw new TemplateNotFoundException(sprintf('No template "%s" for locale %s.', $key, $locale));
        $plain = [];
        $escaped = [];
        foreach ($vars as $name => $value) {
            $string = is_scalar($value) ? (string) $value : '';
            $plain['{' . $name . '}'] = $string;
            $escaped['{' . $name . '}'] = htmlspecialchars($string, ENT_QUOTES);
        }

        return new Rendered(
            strtr($parts['text'], $plain),
            isset($parts['subject']) ? strtr($parts['subject'], $plain) : null,
            isset($parts['html']) ? strtr($parts['html'], $escaped) : null,
        );
    }

    /**
     * @return array{subject?: string, text: string, html?: string}|null
     */
    private function bundled(string $key, string $locale): ?array
    {
        $text = $this->translator->translate($key . '.text', $locale);
        if ($text === null) {
            return null;
        }
        $parts = ['text' => $text];
        $subject = $this->translator->translate($key . '.subject', $locale);
        if ($subject !== null) {
            $parts['subject'] = $subject;
        }
        $html = $this->translator->translate($key . '.html', $locale);
        if ($html !== null) {
            $parts['html'] = $html;
        }

        return $parts;
    }
}
