<?php

declare(strict_types=1);

namespace Polaris\MultiSession;

use LogicException;
use Override;
use Polaris\MultiSession\Http\DeviceMiddleware;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;

use function dirname;

/**
 * The multi-session plugin: `new MultiSessionPlugin()` in `Config::$plugins`. Its middleware records every
 * token pair a response carries against the device (a server-minted id sent back as the
 * `X-Polaris-Device` header and, unless `cookie: false`, the HttpOnly cookie `polaris_ms_device`); the
 * client lists the device's accounts, switches to one without signing in again, revokes one, and reads
 * the device's last sign-in method.
 */
final class MultiSessionPlugin extends AbstractPlugin
{
    public const string ID = 'multi-session';

    public function __construct(private readonly bool $cookie = true)
    {
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The multi-session plugin is not registered.');
        }

        return $plugin;
    }

    #[Override]
    public function id(): string
    {
        return self::ID;
    }

    #[Override]
    public function schema(): array
    {
        return Schema::models();
    }

    #[Override]
    public static function manifestDirectory(): string
    {
        return dirname(__DIR__) . '/api';
    }

    #[Override]
    public function services(): array
    {
        return [
            Devices::class => static fn(Graph $graph): Devices => new Devices($graph->database(), $graph->users(), $graph->tokens(), $graph->principals(), $graph->clock()),
        ];
    }

    #[Override]
    public function middleware(Graph $graph): array
    {
        return [new DeviceMiddleware($graph->get(Devices::class), $graph->tokenFactory(), $this->cookie)];
    }
}
