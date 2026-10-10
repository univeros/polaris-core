<?php

declare(strict_types=1);

namespace Polaris\Mcp\Server;

use Mcp\Schema\Content\TextContent;
use Mcp\Schema\Result\CallToolResult;
use Mcp\Server\ClientGateway;
use Mcp\Server\Handler\ToolHandlerInterface;
use Override;
use Polaris\Mcp\Tool;

use function is_string;
use function json_encode;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * A {@see Tool} as the SDK runs it: the call's `{status, body}` is the `structuredContent`, the text
 * content is the body (as JSON unless it already is text), and a 4xx or 5xx status is an error.
 */
final class ToolHandler implements ToolHandlerInterface
{
    public function __construct(private readonly Tool $tool)
    {
    }

    #[Override]
    public function execute(array $arguments, ClientGateway $gateway): CallToolResult
    {
        $result = ($this->tool->call)($arguments);
        $body = $result['body'];
        $text = is_string($body) ? $body : json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);

        return new CallToolResult([new TextContent($text)], $result['status'] >= 400, ['status' => $result['status'], 'body' => $body]);
    }
}
