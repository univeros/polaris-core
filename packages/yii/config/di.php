<?php

declare(strict_types=1);

use Polaris\Config\AuthConfig;
use Polaris\Config\RateLimitConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Pdo\PdoAdapter;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Yii\Auth\PolarisAuthenticationFailureHandler;
use Polaris\Yii\Auth\PolarisAuthenticationMethod;
use Polaris\Yii\Factory;
use Polaris\Yii\Mail\OtpMailer;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Yiisoft\Auth\AuthenticationMethodInterface;
use Yiisoft\Auth\Middleware\Authentication;

/** @var array $params */
$polaris = $params['polaris'];

return [
    Secrets::class => static fn (): Secrets => Factory::secrets($polaris['secrets'], $polaris['root_path']),
    AuthConfig::class => static fn (): AuthConfig => AuthConfig::fromArray($polaris['auth']),
    RateLimitConfig::class => static fn (): RateLimitConfig => RateLimitConfig::fromArray($polaris['rate_limits']),
    ...($polaris['database']['dsn'] !== null ? [
        PDO::class => static fn (): PDO => Factory::connect($polaris['database']['dsn'], $polaris['database']['user'], $polaris['database']['password']),
    ] : []),
    DatabaseAdapter::class => static fn (ContainerInterface $container): DatabaseAdapter => new PdoAdapter(Factory::pdo($container)),
    Config::class => static fn (ContainerInterface $container): Config => Factory::config($container, $polaris),
    Polaris::class => static fn (Config $config): Polaris => Polaris::create($config),
    Graph::class => static fn (Polaris $service): Graph => $service->graph(),
    Pipeline::class => static fn (Graph $graph, ResponseFactoryInterface $responses): Pipeline => new Pipeline($graph, $responses, $polaris['path_prefix']),
    OtpMailer::class => static fn (ContainerInterface $container): OtpMailer => new OtpMailer($container->get('Yiisoft\Mailer\MailerInterface'), $polaris['mail_from']),
    AuthenticationMethodInterface::class => PolarisAuthenticationMethod::class,
    // The middleware for the application's own routes: `->middleware('polaris/authentication')`.
    'polaris/authentication' => static fn (ContainerInterface $container): Authentication => new Authentication(
        $container->get(PolarisAuthenticationMethod::class),
        $container->get(ResponseFactoryInterface::class),
        $container->get(PolarisAuthenticationFailureHandler::class),
    ),
];
