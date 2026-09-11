<?php

declare(strict_types=1);

namespace Polaris\Messaging\Template;

/**
 * The strings of the templates by id (`email.verify.subject`) and locale; a host plugs its own
 * translator, the bundled {@see ArrayTranslator} ships en, es, de, fr and pt.
 */
interface Translator
{
    public function translate(string $id, string $locale): ?string;
}
