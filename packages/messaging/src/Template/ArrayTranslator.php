<?php

declare(strict_types=1);

namespace Polaris\Messaging\Template;

use Override;

use function dirname;
use function is_array;
use function is_file;
use function is_string;

/**
 * The bundled strings (`resources/translations/<locale>.php`, each returning `id => string`), plus any
 * the application adds or overrides.
 */
final class ArrayTranslator implements Translator
{
    /** @var array<string, array<string, string>> locale => id => string */
    private array $loaded = [];

    /**
     * @param array<string, array<string, string>> $strings locale => id => string, over the bundled ones
     */
    public function __construct(private readonly array $strings = [])
    {
    }

    #[Override]
    public function translate(string $id, string $locale): ?string
    {
        $string = $this->strings[$locale][$id] ?? $this->bundled($locale)[$id] ?? null;

        return is_string($string) ? $string : null;
    }

    /**
     * @return array<string, string>
     */
    private function bundled(string $locale): array
    {
        if (!isset($this->loaded[$locale])) {
            $file = dirname(__DIR__, 2) . '/resources/translations/' . $locale . '.php';
            $strings = is_file($file) ? require $file : [];
            $this->loaded[$locale] = is_array($strings) ? $strings : [];
        }

        return $this->loaded[$locale];
    }
}
