<?php

declare(strict_types=1);

namespace Polaris\Username;

use LogicException;
use Override;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;

use function dirname;

/**
 * The username plugin: `new UsernamePlugin()` in `Config::$plugins`. A user sets a username
 * (`PATCH /username`) and signs in with it or with the email (`POST /username/sign-in`, core's password
 * path: lockout, the MFA gate and the envelope are core's). Usernames are unique without regard to case;
 * the display form is kept as typed.
 */
final class UsernamePlugin extends AbstractPlugin
{
    public const string ID = 'username';

    /** The sign-in route for sentinel's `routes` option (path => attempt kind). */
    public const array SENTINEL_ROUTES = ['/username/sign-in' => 'sign_in'];

    public function __construct(private readonly Rules $rules = new Rules())
    {
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The username plugin is not registered.');
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
            Usernames::class => fn(Graph $graph): Usernames => new Usernames($graph->database(), $graph->clock(), $this->rules),
        ];
    }
}
