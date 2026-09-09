<?php

declare(strict_types=1);

namespace Polaris\Schema;

enum FieldType: string
{
    case String = 'string';
    case Text = 'text';
    case Int = 'int';
    case Bool = 'bool';
    case DateTime = 'datetime';
    case Json = 'json';
}
