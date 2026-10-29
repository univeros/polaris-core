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
    /** What a route does to the caller's session: opens one, rotates it, ends it (cookie token delivery follows it). */
    public const array SESSIONS = ['issue', 'refresh', 'end'];

    /**
     * @param list<string> $tags
     * @param list<string> $requiresPermissions
     * @param list<FieldSpec> $fields
     * @param class-string $class
     * @param array<string, array<string, mixed>> $outputExamples the `output.example` and `output.example_*` bodies, by key
     * @param list<array{status: int, code: string|null}> $errors
     * @param list<string> $events
     * @param string|null $plugin the id of the plugin that declares the route (`admin`), null for core's
     * @param string|null $session one of {@see self::SESSIONS}, null when the route leaves the session alone
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
        public array $outputExamples,
        public array $errors,
        public array $events,
        public ?string $plugin = null,
        public ?string $session = null,
    ) {
    }

    public function route(): string
    {
        return $this->method . ' ' . $this->path;
    }
}
