<?php

declare(strict_types=1);

namespace Polaris\Tests\Support;

use Override;
use Polaris\Contract\MetricsInterface;

final class RecordingMetrics implements MetricsInterface
{
    /** @var list<object{name: string, value: float, attributes: array<string, string>}> */
    private array $points = [];

    #[Override]
    public function counter(string $name, float $value = 1.0, array $attributes = [], ?string $description = null): void
    {
        $this->points[] = (object) ['name' => $name, 'value' => $value, 'attributes' => $attributes];
    }

    /**
     * @return list<object{name: string, value: float, attributes: array<string, string>}>
     */
    public function metrics(): array
    {
        return $this->points;
    }
}
