<?php

declare(strict_types=1);

namespace Polaris\Mcp\Server;

use Polaris\Cli\Application;
use Polaris\Mcp\Tool;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

use function is_array;
use function is_bool;
use function is_scalar;
use function str_replace;

/**
 * The read-only `bin/polaris` commands as tools, over stdio only (a local coding agent's diagnostics,
 * never reachable over HTTP): `polaris.schema.export`, `polaris.schema.diff`, `polaris.manifest`,
 * `polaris.doctor`, run in-process through the console application with the command's options as the
 * tool's arguments; the output is the tool's text, a non-zero exit is an error.
 */
final class CliTools
{
    public const array COMMANDS = ['schema:export', 'schema:diff', 'manifest', 'doctor'];

    private function __construct()
    {
    }

    /**
     * @return list<Tool>
     */
    public static function tools(): array
    {
        $application = new Application();
        $tools = [];
        foreach (self::COMMANDS as $name) {
            $command = $application->find($name);
            $tools[] = new Tool(
                ToolSchema::PREFIX . str_replace(':', '.', $name),
                $command->getDescription() . ' (bin/polaris ' . $name . ')',
                self::schema($command),
                static fn(array $arguments): array => self::run($name, $arguments),
                readOnly: true,
            );
        }

        return $tools;
    }

    /**
     * @return array<string, mixed>
     */
    private static function schema(Command $command): array
    {
        $properties = [];
        foreach ($command->getDefinition()->getOptions() as $option) {
            $properties[$option->getName()] = [
                ...($option->acceptValue() ? ($option->isArray() ? ['type' => 'array', 'items' => ['type' => 'string']] : ['type' => 'string']) : ['type' => 'boolean']),
                'description' => $option->getDescription(),
            ];
        }

        return ['type' => 'object', 'properties' => $properties];
    }

    /**
     * @param array<string, mixed> $arguments
     * @return array{status: int, body: mixed}
     */
    private static function run(string $name, array $arguments): array
    {
        $input = ['command' => $name];
        foreach ($arguments as $option => $value) {
            if (is_bool($value)) {
                if ($value) {
                    $input['--' . $option] = true;
                }
            } elseif (is_scalar($value) || is_array($value)) {
                $input['--' . $option] = $value;
            }
        }
        $application = new Application();
        $application->setAutoExit(false);
        $application->setCatchExceptions(true);
        $output = new BufferedOutput();
        $exit = $application->run(new ArrayInput($input), $output);

        return ['status' => $exit === Command::SUCCESS ? 200 : 500, 'body' => $output->fetch()];
    }
}
