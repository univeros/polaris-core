<?php

declare(strict_types=1);

namespace Polaris\Tests\Support\Plugin;

use Override;
use Polaris\Contract\MfaFactorType;
use Polaris\Contract\MfaFactorTypeProvider;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;

/**
 * A plugin for the seam's tests: registers the factor types it is given.
 */
final class StampPlugin extends AbstractPlugin implements MfaFactorTypeProvider
{
    /**
     * @param list<MfaFactorType> $types
     */
    public function __construct(private readonly array $types)
    {
    }

    #[Override]
    public function id(): string
    {
        return 'stamp';
    }

    #[Override]
    public function mfaFactorTypes(Graph $graph): array
    {
        return $this->types;
    }
}
