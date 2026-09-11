<?php

declare(strict_types=1);

namespace Polaris\Tests\Support\Plugin;

use Polaris\Repository\UserRepository;

/**
 * A plugin service built by the graph from the plugin's factory; it takes a core service to prove
 * factories see the graph.
 */
final class SampleNotes
{
    public function __construct(private readonly UserRepository $users)
    {
    }

    /**
     * @return list<array{id: string, text: string}>
     */
    public function all(): array
    {
        return [['id' => 'n1', 'text' => 'hello'], ['id' => 'n2', 'text' => 'repository: ' . $this->users::class]];
    }
}
