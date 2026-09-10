<?php

declare(strict_types=1);

namespace Polaris\Yii\Tests;

use HttpSoft\Message\ServerRequestFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Yii\Auth\PolarisAuthenticationFailureHandler;
use Polaris\Yii\Auth\PolarisAuthenticationMethod;
use Polaris\Yii\Auth\PolarisIdentity;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\Auth\Middleware\Authentication;
use Yiisoft\Di\Container;
use Yiisoft\Router\Route;

use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

#[CoversClass(PolarisAuthenticationMethod::class)]
#[CoversClass(PolarisIdentity::class)]
#[CoversClass(PolarisAuthenticationFailureHandler::class)]
final class AuthenticationTest extends TestCase
{
    private Container $container;
    private string $userId;
    private string $accessToken;

    protected function setUp(): void
    {
        $protected = Route::get('/protected')->middleware('polaris/authentication')->action(
            static function (ServerRequestInterface $request, ResponseFactoryInterface $responses): ResponseInterface {
                $identity = $request->getAttribute(Authentication::class);
                $response = $responses->createResponse(200)->withHeader('Content-Type', 'application/json');
                $response->getBody()->write(json_encode([
                    'id' => $identity instanceof PolarisIdentity ? $identity->getId() : null,
                    'roles' => $identity instanceof PolarisIdentity ? $identity->claim('roles') : null,
                ], JSON_THROW_ON_ERROR));

                return $response;
            },
        );
        $this->container = YiiApp::container(
            definitions: [Secrets::class => Fixtures::secrets(), AuthConfig::class => Fixtures::auth(), DatabaseAdapter::class => new InMemoryAdapter()],
            routes: [$protected],
        );
        ['id' => $this->userId, 'token' => $this->accessToken] = Fixtures::userWithToken($this->container->get(Graph::class));
    }

    public function testAValidBearerAuthenticatesThePolarisIdentity(): void
    {
        $response = $this->handle('Bearer ' . $this->accessToken);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame($this->userId, $body['id']);
        self::assertSame(['owner'], $body['roles']);
    }

    public function testAnInvalidBearerIsUnauthorized(): void
    {
        $response = $this->handle('Bearer not-a-token');

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer', $response->getHeaderLine('WWW-Authenticate'));
        self::assertSame('unauthorized', json_decode((string) $response->getBody(), true)['error']);
    }

    public function testNoBearerIsUnauthorized(): void
    {
        $response = $this->handle(null);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer', $response->getHeaderLine('WWW-Authenticate'));
    }

    private function handle(?string $authorization): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', '/protected');
        if ($authorization !== null) {
            $request = $request->withHeader('Authorization', $authorization);
        }

        return YiiApp::handle($this->container, $request);
    }
}
