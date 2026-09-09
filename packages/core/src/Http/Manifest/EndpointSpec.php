<?php

declare(strict_types=1);

namespace Polaris\Http\Manifest;

/**
 * One `api/**\/*.yaml` file: the route, its policy, its input and the endpoint class serving it.
 */
final readonly class EndpointSpec
{
    public const array AUTH = ['public', 'bearer', 'mfa_token'];
    public const array EFFECTS = ['read', 'write', 'destructive'];
    public const array SOURCES = ['body', 'path', 'query', 'none'];

    /**
     * @param list<string> $tags
     * @param list<string> $requiresPermissions
     * @param list<FieldSpec> $fields
     * @param class-string $class
     * @param list<array{status: int, code: string|null}> $errors
     * @param list<string> $events
     */
    public function __construct(
        public string $file,
        public string $method,
        public string $path,
        public string $summary,
        public array $tags,
        public string $auth,
        public ?string $rateLimit,
        public string $effect,
        public bool $receipt,
        public bool $stepUp,
        public array $requiresPermissions,
        public string $inputSource,
        public array $fields,
        public string $class,
        public ?int $outputStatus,
        public array $errors,
        public array $events,
    ) {
    }

    public function route(): string
    {
        return $this->method . ' ' . $this->path;
    }
}
