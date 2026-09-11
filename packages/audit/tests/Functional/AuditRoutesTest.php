<?php

declare(strict_types=1);

namespace Polaris\Audit\Tests\Functional;

use Override;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Event\UserRegistered;
use Polaris\Tests\Contract\Fixture;
use Polaris\Tests\Functional\FunctionalTestCase;

use function array_column;
use function dirname;

/**
 * The audit routes through the pipeline (and, with `POLARIS_HARNESS`, through every host): the events
 * the auth flows emit are readable per user and per organization, filtered and paginated; the
 * recorded steps in tests/Contract/fixtures replay identically.
 */
final class AuditRoutesTest extends FunctionalTestCase
{
    private const string EMAIL = 'ada@example.com';
    private const string PASSWORD = 'correct horse battery staple';

    #[Override]
    protected static function plugins(): array
    {
        return [new AuditPlugin()];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    public function testTheCallersTrailListsTheAuthFlowNewestFirstWithFiltersAndPages(): void
    {
        $access = $this->registerVerifyLogin();

        $me = $this->json($this->authedGet('/audit/me', $access));
        self::assertSame([Catalog::SESSION_SIGNED_IN, Catalog::USER_EMAIL_VERIFIED, Catalog::USER_SIGNED_UP], array_column($me['data'], 'name'));
        self::assertNull($me['next_cursor']);
        self::assertSame(['email' => self::EMAIL], $me['data'][2]['data'], 'no verification token in the data');
        self::assertSame('user', $me['data'][0]['actor_type']);
        self::assertNotNull($me['data'][0]['session_id']);

        $filtered = $this->json($this->authedGet('/audit/me?names=' . Catalog::USER_SIGNED_UP, $access));
        self::assertSame([Catalog::USER_SIGNED_UP], array_column($filtered['data'], 'name'));

        $first = $this->json($this->authedGet('/audit/me?limit=2', $access));
        self::assertCount(2, $first['data']);
        self::assertSame($first['data'][1]['id'], $first['next_cursor']);
        $second = $this->json($this->authedGet('/audit/me?limit=2&cursor=' . $first['next_cursor'], $access));
        self::assertSame([Catalog::USER_SIGNED_UP], array_column($second['data'], 'name'));
        self::assertNull($second['next_cursor']);

        $invalid = $this->authedGet('/audit/me?from=yesterday-ish-nonsense', $access);
        self::assertSame(422, $invalid->getStatusCode());
        self::assertSame('application/problem+json', $invalid->getHeaderLine('Content-Type'));
        self::assertSame('audit_invalid_query', $this->json($invalid)['error']);

        self::assertSame(401, $this->get('/audit/me')->getStatusCode());
    }

    public function testTheCatalogIsListedForASession(): void
    {
        $access = $this->registerVerifyLogin();

        $types = $this->json($this->authedGet('/audit/types', $access));
        self::assertContains(Catalog::SESSION_SIGNED_IN, array_column($types['data'], 'name'));
        self::assertSame(401, $this->get('/audit/types')->getStatusCode());
    }

    public function testAnOrganizationsTrailNeedsTheActiveOrganizationAndAuditRead(): void
    {
        $access = $this->registerVerifyLogin();
        $organization = $this->json($this->authedPostJson('/orgs', ['name' => 'Acme Rockets'], $access))['data']['id'];
        $other = $this->json($this->authedPostJson('/orgs', ['name' => 'Globex'], $access))['data']['id'];
        $scoped = $this->json($this->authedPostJson('/auth/switch-org', ['organization_id' => $organization], $access))['data']['access_token'];

        $trail = $this->json($this->authedGet('/audit/organization/' . $organization, $scoped));
        self::assertSame([Catalog::SESSION_ORGANIZATION_SWITCHED, Catalog::ORG_CREATED], array_column($trail['data'], 'name'));
        self::assertSame($organization, $trail['data'][1]['organization_id']);

        $forbidden = $this->authedGet('/audit/organization/' . $other, $scoped);
        self::assertSame(403, $forbidden->getStatusCode());
        self::assertSame('audit_forbidden', $this->json($forbidden)['error']);
        self::assertSame(403, $this->authedGet('/audit/organization/' . $organization, $access)->getStatusCode(), 'an unscoped token has no organization permission');
        self::assertSame(401, $this->get('/audit/organization/' . $organization)->getStatusCode());
    }

    private function registerVerifyLogin(): string
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $token = $this->events->ofType(UserRegistered::class)[0]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();

        return (string) ($this->json($this->postJson('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]))['data']['access_token'] ?? '');
    }
}
