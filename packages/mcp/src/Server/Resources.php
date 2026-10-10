<?php

declare(strict_types=1);

namespace Polaris\Mcp\Server;

use Closure;
use Mcp\Schema\ResourceDefinition;
use Mcp\Schema\ResourceTemplate;
use Mcp\Server\ClientGateway;
use Mcp\Server\Handler\ResourceHandlerInterface;
use Mcp\Server\Handler\ResourceTemplateHandlerInterface;
use Override;
use Polaris\Http\Endpoint;
use Polaris\Http\Manifest\OpenApi;
use Polaris\Wiring\Graph;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Polaris\Cli\Application;

use function array_keys;
use function in_array;
use function is_string;
use function json_encode;
use function sort;
use function str_replace;
use function ucwords;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * The server's resources: `polaris://manifest` (the OpenAPI document of every route, core and
 * plugins), `polaris://schema` (the DDL `bin/polaris schema:export` prints), and the template
 * `polaris://problems/{plugin}/{name}` (a plugin's problem type as the manifest declares it: its URL,
 * the statuses and routes it is answered on).
 */
final class Resources
{
    public const string MANIFEST = 'polaris://manifest';
    public const string SCHEMA = 'polaris://schema';
    public const string PROBLEMS = 'polaris://problems/{plugin}/{name}';

    public function __construct(private readonly Graph $graph)
    {
    }

    /**
     * @return list<array{ResourceDefinition, ResourceHandlerInterface}>
     */
    public function definitions(): array
    {
        return [
            [
                new ResourceDefinition(self::MANIFEST, 'manifest', 'The Polaris manifest', 'OpenAPI 3.1 document of every Polaris route, core and plugins.', 'application/json'),
                self::reader(fn(): string => json_encode(OpenApi::document($this->graph->manifest()), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)),
            ],
            [
                new ResourceDefinition(self::SCHEMA, 'schema', 'The Polaris schema', 'The DDL of every Polaris table (core and plugins) for PostgreSQL, as bin/polaris schema:export prints it.', 'text/x-sql'),
                self::reader(static fn(): string => self::schemaExport()),
            ],
        ];
    }

    /**
     * @return array{ResourceTemplate, ResourceTemplateHandlerInterface}
     */
    public function problems(): array
    {
        $graph = $this->graph;

        return [
            new ResourceTemplate(self::PROBLEMS, 'problem', 'A problem type', 'An RFC 9457 problem type a plugin answers (https://polaris.univeros.io/problems/<plugin>/<name>): its statuses and routes.', 'application/json'),
            new class ($graph) implements ResourceTemplateHandlerInterface {
                public function __construct(private readonly Graph $graph)
                {
                }

                #[Override]
                public function read(string $uri, array $variables, ClientGateway $gateway): string
                {
                    $plugin = is_string($variables['plugin'] ?? null) ? $variables['plugin'] : '';
                    $name = is_string($variables['name'] ?? null) ? $variables['name'] : '';
                    $statuses = [];
                    $routes = [];
                    foreach ($this->graph->manifest()->endpoints() as $spec) {
                        if ($spec->plugin !== $plugin) {
                            continue;
                        }
                        foreach ($spec->errors as $error) {
                            if (in_array($error['code'], [$name, $plugin . '_' . $name], true)) {
                                $statuses[$error['status']] = true;
                                $routes[$spec->route()] = true;
                            }
                        }
                    }
                    if ($routes === []) {
                        throw new \InvalidArgumentException('No plugin declares the problem ' . $plugin . '/' . $name . '.');
                    }
                    $codes = array_keys($statuses);
                    sort($codes);

                    return json_encode([
                        'type' => Endpoint::PROBLEM_TYPES . $plugin . '/' . $name,
                        'title' => ucwords(str_replace('_', ' ', $name)),
                        'status' => $codes,
                        'routes' => array_keys($routes),
                    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
                }
            },
        ];
    }

    /**
     * @param Closure(): string $read
     */
    private static function reader(Closure $read): ResourceHandlerInterface
    {
        return new class ($read) implements ResourceHandlerInterface {
            /**
             * @param Closure(): string $read
             */
            public function __construct(private readonly Closure $read)
            {
            }

            #[Override]
            public function read(string $uri, ClientGateway $gateway): string
            {
                return ($this->read)();
            }
        };
    }

    private static function schemaExport(): string
    {
        $application = new Application();
        $application->setAutoExit(false);
        $output = new BufferedOutput();
        if ($application->run(new ArrayInput(['command' => 'schema:export']), $output) !== Command::SUCCESS) {
            throw new \RuntimeException('schema:export failed.');
        }

        return $output->fetch();
    }
}
