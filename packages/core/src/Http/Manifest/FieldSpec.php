<?php

declare(strict_types=1);

namespace Polaris\Http\Manifest;

use Polaris\Http\Validation\Rule;

final readonly class FieldSpec
{
    /**
     * @param list<Rule> $rules
     */
    public function __construct(
        public string $name,
        public string $type,
        public array $rules,
        public bool $sensitive,
    ) {
    }
}
