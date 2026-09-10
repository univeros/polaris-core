<?php

declare(strict_types=1);

namespace Polaris\Laravel\Tests;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Log\LogManager;
use PHPUnit\Framework\Attributes\CoversClass;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\Dialect;
use Polaris\Exception\InvalidConfigException;
use Polaris\Laravel\Events\EventBridge;
use Polaris\Laravel\Mail\OtpMailer;
use Polaris\Laravel\PolarisFactory;
use Polaris\Mfa\LogOtpMailer;
use Polaris\Mfa\LogSmsSender;
use Polaris\Polaris;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\RecordingOtpMailer;
use Polaris\Tests\Support\RecordingSmsSender;
use Polaris\Tests\Support\TestKeys;
use Polaris\Wiring\Graph;
use stdClass;

use function bin2hex;
use function file_put_contents;
use function random_bytes;
use function str_repeat;
use function sys_get_temp_dir;
use function trim;
use function unlink;

#[CoversClass(PolarisFactory::class)]
final class PolarisFactoryTest extends LaravelTestCase
{
    /** @var array{private: string, public: string} */
    private array $keys;

    protected function setUp(): void
    {
        parent::setUp();
        $this->keys = TestKeys::rsa();
    }

    public function testBuildsPolarisFromTheConfigurationAndTheApplicationServices(): void
    {
        $app = LaravelApp::create([
            'secrets' => ['app_key' => str_repeat('k', 32), 'jwt_private_key' => $this->keys['private'], 'jwt_public_key' => $this->keys['public'], 'jwt_kid' => 'test'],
            'auth' => ['issuer' => 'https://issuer.test', 'access_token' => ['denylist' => 'on'], 'password' => ['breach_check' => 'false']],
            'rate_limits' => ['login' => ['limit' => 3]],
            'database' => 'polaris_test',
            'cache' => 'array',
            'path_prefix' => '/api/auth',
        ]);
        $app->make(Repository::class)->set('database.connections.polaris_test', ['driver' => 'sqlite', 'database' => ':memory:']);

        $graph = $app->make(Graph::class);

        self::assertSame('https://issuer.test', $graph->config()->auth->issuer);
        self::assertTrue($graph->config()->auth->accessToken->denylist);
        self::assertFalse($graph->config()->auth->breachCheck);
        self::assertSame(3, $graph->rateLimits()->login->limit);
        self::assertSame('test', $graph->config()->secrets->jwtKid);
        self::assertSame(Dialect::Sqlite, $graph->database()->dialect());
        self::assertInstanceOf(CacheRepository::class, $graph->cache());
        self::assertInstanceOf(LogManager::class, $graph->logger());
        self::assertInstanceOf(EventBridge::class, $graph->events());
        self::assertInstanceOf(LogOtpMailer::class, $graph->mailer());
        self::assertInstanceOf(LogSmsSender::class, $graph->sms());
        self::assertSame('/api/auth', $graph->config()->pathPrefix);
        self::assertSame($app->make(Polaris::class), $app->make(Polaris::class));
    }

    public function testPortsAcceptInstancesAndContainerBindings(): void
    {
        $secrets = Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $this->keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $this->keys['public']]);
        $auth = AuthConfig::fromArray(['issuer' => 'https://issuer.test']);
        $adapter = new InMemoryAdapter();
        $sms = new RecordingSmsSender();
        $app = LaravelApp::create([
            'secrets' => $secrets,
            'auth' => $auth,
            'database' => $adapter,
            'mailer' => RecordingOtpMailer::class,
            'sms' => $sms,
        ]);
        $mailer = new RecordingOtpMailer();
        $app->instance(RecordingOtpMailer::class, $mailer);

        $graph = $app->make(Graph::class);

        self::assertSame($secrets, $graph->config()->secrets);
        self::assertSame($auth, $graph->config()->auth);
        self::assertSame($adapter, $graph->database());
        self::assertSame($mailer, $graph->mailer());
        self::assertSame($sms, $graph->sms());
    }

    public function testMailSendsThroughLaravelsMailerWithThePolarisViews(): void
    {
        $app = LaravelApp::create([
            'secrets' => ['app_key' => str_repeat('k', 32), 'jwt_private_key' => $this->keys['private'], 'jwt_public_key' => $this->keys['public']],
            'auth' => ['issuer' => 'https://issuer.test'],
            'database' => new InMemoryAdapter(),
            'mailer' => 'mail',
        ]);
        $app->make(Repository::class)->set('mail.default', 'array');
        $mailer = $app->make(Graph::class)->mailer();
        self::assertInstanceOf(OtpMailer::class, $mailer);

        $mailer->send('ada@example.com', 'otp_code', ['code' => '123456', 'ttl' => 300]);
        $mailer->send('ada@example.com', 'mfa_enrolled', ['factor_id' => 'f-1']);

        $messages = $app->make('mailer')->getSymfonyTransport()->messages();
        self::assertCount(2, $messages);
        $code = $messages[0]->getOriginalMessage();
        self::assertSame('Your verification code', $code->getSubject());
        self::assertStringContainsString('123456', (string) $code->getTextBody());
        self::assertStringContainsString('300 seconds', (string) $code->getTextBody());
        $generic = $messages[1]->getOriginalMessage();
        self::assertSame('A new authentication factor was added', $generic->getSubject());
        self::assertStringContainsString('factor_id: f-1', (string) $generic->getTextBody());
    }

    public function testSecretFilesAreRead(): void
    {
        $file = sys_get_temp_dir() . '/polaris-' . bin2hex(random_bytes(4)) . '.pem';
        file_put_contents($file, $this->keys['private']);
        try {
            $app = LaravelApp::create([
                'secrets' => ['app_key' => str_repeat('k', 32), 'jwt_private_key_file' => $file, 'jwt_public_key' => $this->keys['public']],
                'auth' => ['issuer' => 'https://issuer.test'],
                'database' => new InMemoryAdapter(),
            ]);
            self::assertSame(trim($this->keys['private']), $app->make(Graph::class)->config()->secrets->jwtPrivateKey);
        } finally {
            unlink($file);
        }
    }

    public function testAMissingSecretFileIsAConfigurationError(): void
    {
        $app = LaravelApp::create([
            'secrets' => ['app_key' => str_repeat('k', 32), 'jwt_private_key_file' => 'storage/keys/nope.pem', 'jwt_public_key' => $this->keys['public']],
            'auth' => ['issuer' => 'https://issuer.test'],
            'database' => new InMemoryAdapter(),
        ]);

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('jwt_private_key_file');
        $app->make(Graph::class);
    }

    public function testAPortOfTheWrongTypeIsAConfigurationError(): void
    {
        $app = LaravelApp::create([
            'secrets' => ['app_key' => str_repeat('k', 32), 'jwt_private_key' => $this->keys['private'], 'jwt_public_key' => $this->keys['public']],
            'auth' => ['issuer' => 'https://issuer.test'],
            'database' => new InMemoryAdapter(),
            'sms' => stdClass::class,
        ]);

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('polaris.sms must be a Polaris\Contract\SmsSenderInterface');
        $app->make(Graph::class);
    }
}
