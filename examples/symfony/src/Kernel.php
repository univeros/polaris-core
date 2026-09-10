<?php

declare(strict_types=1);

namespace PolarisDemo;

use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\HttpKernel\Kernel as BaseKernel;

/**
 * A stock Symfony kernel: config/bundles.php, config/packages/*.yaml, config/routes.yaml.
 */
final class Kernel extends BaseKernel
{
    use MicroKernelTrait;
}
