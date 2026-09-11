<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

use Override;

use function dirname;
use function file;
use function is_file;
use function str_starts_with;
use function strtolower;
use function trim;

use const FILE_IGNORE_NEW_LINES;
use const FILE_SKIP_EMPTY_LINES;

/**
 * A list file, one domain per line (`#` comments), the bundled one by default (`resources/disposable-domains.txt`,
 * from disposable-email-domains, CC0, refreshed per release or with `sentinel:lists`), plus the
 * application's own domains. Loaded once, on first use.
 */
final class FileDomainList implements DomainList
{
    /** @var array<string, true>|null */
    private ?array $domains = null;

    /**
     * @param list<string> $extra
     */
    public function __construct(private readonly ?string $file = null, private readonly array $extra = [])
    {
    }

    public static function bundledFile(): string
    {
        return dirname(__DIR__, 2) . '/resources/disposable-domains.txt';
    }

    #[Override]
    public function contains(string $domain): bool
    {
        return isset($this->load()[strtolower($domain)]);
    }

    /**
     * @return array<string, true>
     */
    private function load(): array
    {
        if ($this->domains !== null) {
            return $this->domains;
        }
        $domains = [];
        $file = $this->file ?? self::bundledFile();
        foreach (is_file($file) ? (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []) : [] as $line) {
            $line = strtolower(trim($line));
            if ($line !== '' && !str_starts_with($line, '#')) {
                $domains[$line] = true;
            }
        }
        foreach ($this->extra as $domain) {
            $domains[strtolower($domain)] = true;
        }

        return $this->domains = $domains;
    }
}
