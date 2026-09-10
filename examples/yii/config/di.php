<?php

declare(strict_types=1);

use HttpSoft\Message\ResponseFactory;
use HttpSoft\Message\ServerRequestFactory;
use HttpSoft\Message\StreamFactory;
use HttpSoft\Message\UploadedFileFactory;
use HttpSoft\Message\UriFactory;
use PolarisDemo\FileMailer;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UploadedFileFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Yiisoft\Cache\File\FileCache;
use Yiisoft\Log\Logger;

// What every Yii application provides: PSR-17 factories, a logger, a cache that outlives a request
// (rate limits, the denylist and OTP quotas live there), and the demo's mailbox.
return [
    ResponseFactoryInterface::class => ResponseFactory::class,
    ServerRequestFactoryInterface::class => ServerRequestFactory::class,
    StreamFactoryInterface::class => StreamFactory::class,
    UriFactoryInterface::class => UriFactory::class,
    UploadedFileFactoryInterface::class => UploadedFileFactory::class,
    LoggerInterface::class => static fn (): Logger => new Logger(),
    CacheInterface::class => static fn (): FileCache => new FileCache(dirname(__DIR__) . '/var/cache'),
    FileMailer::class => static fn (): FileMailer => new FileMailer(dirname(__DIR__) . '/var/mail.log'),
];
