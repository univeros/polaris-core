<?php

declare(strict_types=1);

namespace Polaris\Tests\Support\Plugin;

use Override;
use Polaris\Authorization\Gate;
use Polaris\Contract\BearerResolver;
use Polaris\Contract\BearerResolverProvider;
use Polaris\Contract\TokenInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Token\Token;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Uid\Uuid;

use function explode;
use function str_starts_with;
use function substr;

/**
 * A plugin for the bearer-resolver seam's tests: `Authorization: Bearer stamp:<user>[:<org>]`
 * authenticates as that user with the permissions the test delegated; `Bearer stamp:revoked` is refused.
 */
final class StampResolverPlugin extends AbstractPlugin implements BearerResolverProvider, BearerResolver
{
    public int $asked = 0;

    /**
     * @param list<string>|null $delegated null leaves the owner's full authority
     */
    public function __construct(private readonly ?array $delegated)
    {
    }

    #[Override]
    public function id(): string
    {
        return 'stamp';
    }

    #[Override]
    public function bearerResolvers(Graph $graph): array
    {
        return [$this];
    }

    #[Override]
    public function resolve(ServerRequestInterface $request): ?TokenInterface
    {
        ++$this->asked;
        $header = $request->getHeaderLine('Authorization');
        if (!str_starts_with($header, 'Bearer stamp:')) {
            return null;
        }
        $parts = explode(':', substr($header, 13));
        if ($parts[0] === 'revoked') {
            throw new AuthorizationTokenException('The stamp was revoked.');
        }
        $claims = ['sub' => $parts[0], 'org' => $parts[1] ?? null, 'jti' => Uuid::v7()->toRfc4122(), 'amr' => ['stamp']];
        if ($this->delegated !== null) {
            $claims[Gate::DELEGATED] = $this->delegated;
        }

        return new Token($header, $claims);
    }
}
