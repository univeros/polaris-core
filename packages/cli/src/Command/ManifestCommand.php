<?php

declare(strict_types=1);

namespace Polaris\Cli\Command;

use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Http\Manifest\FieldSpec;
use Polaris\Http\Manifest\Loader;
use Polaris\Http\Manifest\OpenApi;
use Polaris\Http\Validation\Rule;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

use function array_map;
use function json_encode;
use function sprintf;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

final class ManifestCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->setName('manifest')
            ->setDescription('Validates api/**/*.yaml and prints the manifest as JSON or OpenAPI 3.1.')
            ->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'json | openapi', 'json')
            ->addOption('dir', null, InputOption::VALUE_REQUIRED, 'Spec directory', Loader::defaultDirectory());
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $manifest = (new Loader((string) $input->getOption('dir')))->load();
        } catch (Throwable $exception) {
            $output->writeln(sprintf('<error>%s</error>', $exception->getMessage()));

            return Command::FAILURE;
        }
        $format = (string) $input->getOption('format');
        $document = match ($format) {
            'json' => ['endpoints' => array_map(self::endpoint(...), $manifest->endpoints())],
            'openapi' => OpenApi::document($manifest),
            default => null,
        };
        if ($document === null) {
            $output->writeln(sprintf('<error>Unknown format "%s"; use json or openapi.</error>', $format));

            return Command::INVALID;
        }
        $output->writeln(json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

        return Command::SUCCESS;
    }

    /**
     * @return array<string, mixed>
     */
    private static function endpoint(EndpointSpec $spec): array
    {
        return [
            'method' => $spec->method,
            'path' => $spec->path,
            'summary' => $spec->summary,
            'auth' => $spec->auth,
            'rate_limit' => $spec->rateLimit,
            'effect' => $spec->effect,
            'receipt' => $spec->receipt,
            'step_up' => $spec->stepUp,
            'requires_permissions' => $spec->requiresPermissions,
            'input' => ['source' => $spec->inputSource, 'fields' => array_map(static fn(FieldSpec $f): array => ['name' => $f->name, 'type' => $f->type, 'rules' => array_map(static fn(Rule $r): string => $r->argument === null ? $r->name : $r->name . ':' . $r->argument, $f->rules), 'sensitive' => $f->sensitive], $spec->fields)],
            'class' => $spec->class,
            'errors' => $spec->errors,
            'events' => $spec->events,
        ];
    }
}
