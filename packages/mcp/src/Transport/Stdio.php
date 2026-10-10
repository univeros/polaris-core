<?php

declare(strict_types=1);

namespace Polaris\Mcp\Transport;

use Mcp\Server\Builder;
use Mcp\Server\Transport\StdioTransport;
use Psr\Log\LoggerInterface;

use const STDIN;
use const STDOUT;

/**
 * The stdio transport (`bin/polaris mcp`, a local coding agent): the SDK's, reading JSON-RPC lines
 * from the input stream until it closes, answering on the output stream. Streams are parameters so a
 * test drives a server over memory streams.
 */
final class Stdio
{
    public function __construct(private readonly Builder $builder, private readonly ?LoggerInterface $logger = null)
    {
    }

    /**
     * @param resource|null $input
     * @param resource|null $output
     */
    public function run($input = null, $output = null): int
    {
        return (int) $this->builder->build()->run(new StdioTransport($input ?? STDIN, $output ?? STDOUT, $this->logger));
    }
}
