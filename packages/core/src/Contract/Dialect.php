<?php

declare(strict_types=1);

namespace Polaris\Contract;

enum Dialect: string
{
    case Postgres = 'postgres';
    case Mysql = 'mysql';
    case Sqlite = 'sqlite';
    case Mssql = 'mssql';
    /** The in-memory adapter: no SQL is ever generated. */
    case Memory = 'memory';
}
