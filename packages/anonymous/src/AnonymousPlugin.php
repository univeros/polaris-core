<?php

declare(strict_types=1);

namespace Polaris\Anonymous;

use Closure;
use LogicException;
use Override;
use Polaris\Anonymous\Console\PruneCommand;
use Polaris\Cli\CommandProvider;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;

use function dirname;

/**
 * The anonymous plugin: `new AnonymousPlugin(onConvert: fn(string $guestId, string $userId) => ...)` in
 * `Config::$plugins`. `POST /anonymous/sign-in` opens a guest session (`amr: ["anonymous"]`, no
 * organization); once the guest signs into or up for a real account by any method,
 * `POST /anonymous/convert` hands the guest's id and the account's to the host's `onConvert`, ends the
 * guest's sessions and disables it. `polaris anonymous:prune` deletes the guests nobody converted after
 * `pruneAfterDays`.
 */
final class AnonymousPlugin extends AbstractPlugin implements CommandProvider
{
    public const string ID = 'anonymous';

    /** The sign-in route for sentinel's `routes` option (path => attempt kind): a guest is a sign-up. */
    public const array SENTINEL_ROUTES = ['/anonymous/sign-in' => 'sign_up'];

    private readonly ?Closure $onConvert;

    /**
     * @param (callable(string, string): void)|null $onConvert moves the host's data: guest id, account id
     */
    public function __construct(?callable $onConvert = null, private readonly int $pruneAfterDays = 30)
    {
        if ($pruneAfterDays < 1) {
            throw new LogicException('pruneAfterDays must be at least 1.');
        }
        $this->onConvert = $onConvert === null ? null : $onConvert(...);
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The anonymous plugin is not registered.');
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
            Guests::class => fn(Graph $graph): Guests => new Guests(
                $graph->database(),
                $graph->unitOfWork(),
                $graph->users(),
                $graph->tokens(),
                $graph->sessions(),
                $graph->tokenFactory(),
                $graph->events(),
                $graph->clock(),
                $this->onConvert,
                $this->pruneAfterDays,
            ),
        ];
    }

    #[Override]
    public function commands(Graph $graph): array
    {
        return [new PruneCommand(static fn(): Graph => $graph)];
    }
}
