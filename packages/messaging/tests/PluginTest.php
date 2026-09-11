<?php

declare(strict_types=1);

namespace Polaris\Messaging\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Polaris\Cli\Application;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Event\PasswordChanged;
use Polaris\Event\UserRegistered;
use Polaris\Messaging\Bridge\Mailer;
use Polaris\Messaging\Bridge\Sms;
use Polaris\Messaging\Channel\ArrayChannel;
use Polaris\Messaging\Console\SendCommand;
use Polaris\Messaging\Message;
use Polaris\Messaging\MessagePolicy;
use Polaris\Messaging\MessageSent;
use Polaris\Messaging\MessagingPlugin;
use Polaris\Messaging\Schema;
use Polaris\Messaging\Sender;
use Polaris\Messaging\Suppressor;
use Polaris\Model\User;
use Polaris\Polaris;
use Polaris\Schema\Schema as CoreSchema;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\FrozenClock;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\TestKeys;
use Polaris\Wiring\Config;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The plugin wired through `Polaris::create()`: core's mail and SMS ports are its bridges, the
 * notification listener's mails render from its templates, the policy caps and falls back, every
 * delivery is audited. Separate processes: the schema registry is static.
 */
#[CoversClass(MessagingPlugin::class)]
#[CoversClass(Sender::class)]
#[CoversClass(MessagePolicy::class)]
#[CoversClass(Mailer::class)]
#[CoversClass(Sms::class)]
#[CoversClass(MessageSent::class)]
#[CoversClass(SendCommand::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-09-11T10:00:00+00:00';

    public function testThePluginIsCoresMailerAndSmsSenderAndEverySendIsAudited(): void
    {
        $mail = new ArrayChannel('mail', [Message::EMAIL]);
        $sms = new ArrayChannel('sms', [Message::SMS]);
        $events = new RecordingEventDispatcher();
        $polaris = self::polaris(new MessagingPlugin(channels: [$mail, $sms], locale: 'es'), $events);
        $graph = $polaris->graph();
        $events->listen(...$polaris->listeners());

        self::assertCount(19, $polaris->schema(), 'core, audit and the template table');
        self::assertSame(Schema::TEMPLATES, CoreSchema::for(\Polaris\Messaging\Model\Template::class)->table);
        self::assertInstanceOf(Mailer::class, $graph->mailer());
        self::assertInstanceOf(Sms::class, $graph->sms());
        self::assertTrue($graph->get(Catalog::class)->has(MessageSent::NAME));

        $events->dispatch(new UserRegistered('u1', 'ada@example.com', 'tok-1'));
        self::assertCount(1, $mail->messages, 'the notification listener sent through the plugin');
        $verify = $mail->messages[0];
        self::assertSame(['email', 'ada@example.com', 'email.verify', 'Verifica tu dirección de correo'], [$verify->kind, $verify->to, $verify->template, $verify->subject]);
        self::assertStringContainsString('tok-1', $verify->text);
        self::assertTrue($verify->essential);

        $graph->sms()->send('+15551234567', 'Your verification code is 123456.');
        self::assertSame('Your verification code is 123456.', $sms->messages[0]->text);
        self::assertSame('sms.otp', $sms->messages[0]->template);

        $user = new User();
        $user->id = 'u1';
        $user->email = 'ada@example.com';
        $user->createdAt = $user->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();
        $events->dispatch(new PasswordChanged('u1', PasswordChanged::METHOD_RESET));
        self::assertSame('email.password_changed', $mail->messages[1]->template);
        self::assertFalse($mail->messages[1]->essential);

        $recorded = $graph->get(Store::class)->read(new AuditQuery(names: [MessageSent::NAME]))->events;
        self::assertCount(3, $recorded);
        self::assertSame(['email.password_changed', 'sms.otp', 'email.verify'], array_map(static fn($event): string => $event->data['template'], $recorded));
        self::assertSame(hash('sha256', 'ada@example.com'), $recorded[2]->data['recipient_hash']);
        self::assertSame('mail-1', $recorded[2]->data['provider_id']);
        self::assertArrayNotHasKey('text', $recorded[2]->data, 'never the body');
        self::assertSame('system', $recorded[2]->actorType);
    }

    public function testTheConfiguredMailerWinsOverThePlugin(): void
    {
        $recording = new \Polaris\Tests\Support\RecordingOtpMailer();
        $polaris = self::polaris(new MessagingPlugin(channels: [new ArrayChannel()]), new RecordingEventDispatcher(), $recording);

        self::assertSame($recording, $polaris->graph()->mailer());
        self::assertInstanceOf(Sms::class, $polaris->graph()->sms(), 'the unset port is still the plugin\'s');
    }

    public function testThePolicyCapsRecipientsFallsBackAndKeepsQuiet(): void
    {
        $mail = new ArrayChannel('mail', [Message::EMAIL]);
        $sms = new ArrayChannel('sms', [Message::SMS], failing: true);
        $quiet = new class implements Suppressor {
            public bool $on = false;

            public function suppresses(Message $message): bool
            {
                return $this->on;
            }
        };
        $polaris = self::polaris(new MessagingPlugin(channels: [$sms, $mail], caps: ['*' => [2, 600], 'email.otp' => [1, 600]], suppressor: $quiet), new RecordingEventDispatcher());
        $sender = $polaris->graph()->get(Sender::class);

        self::assertNotNull($sender->send(Message::EMAIL, 'ada@example.com', 'email.verify', ['token' => 't']));
        self::assertNotNull($sender->send(Message::EMAIL, 'ADA@example.com', 'email.verify', ['token' => 't']));
        self::assertNull($sender->send(Message::EMAIL, 'ada@example.com', 'email.verify', ['token' => 't']), 'the third in the window is refused, case-insensitively');
        self::assertNotNull($sender->send(Message::EMAIL, 'bob@example.com', 'email.verify', ['token' => 't']), 'another recipient has their own cap');
        self::assertNotNull($sender->send(Message::EMAIL, 'ada@example.com', 'email.otp', ['code' => 1, 'ttl' => 9]));
        self::assertNull($sender->send(Message::EMAIL, 'ada@example.com', 'email.otp', ['code' => 1, 'ttl' => 9]), 'the template cap');
        self::assertCount(4, $mail->messages);

        $receipt = $sender->send(Message::SMS, '+15551234567', 'sms.otp', ['code' => 7], alternatives: [Message::EMAIL => 'ada@example.com']);
        self::assertSame('mail', $receipt?->channel, 'the SMS channel failed, the email sibling went instead');
        self::assertSame(['email.otp', 'Your verification code is 7. It expires in {ttl} seconds.'], [$mail->messages[4]->template, $mail->messages[4]->text]);
        self::assertNull($sender->send(Message::SMS, '+15557654321', 'sms.otp', ['code' => 7]), 'no alternative, no fallback');

        $quiet->on = true;
        self::assertNull($sender->send(Message::EMAIL, 'carol@example.com', 'email.new_device', ['ip' => '1', 'user_agent' => 'x']), 'quiet mode drops a non-essential message');
        self::assertNotNull($sender->send(Message::EMAIL, 'carol@example.com', 'email.verify', ['token' => 't'], essential: true), 'an essential one still goes');
    }

    public function testTheSendCommandRunsOnTheApplicationsGraph(): void
    {
        $mail = new ArrayChannel('mail', [Message::EMAIL]);
        $polaris = self::polaris(new MessagingPlugin(channels: [$mail]), new RecordingEventDispatcher());
        $app = new Application($polaris);
        $app->setAutoExit(false);

        $send = new CommandTester($app->find('messaging:send'));
        self::assertSame(0, $send->execute(['to' => 'ada@example.com', 'template' => 'email.otp', '--vars' => '{"code":"424242","ttl":300}', '--locale' => 'fr']));
        self::assertStringContainsString('Sent email.otp to ada@example.com through mail', $send->getDisplay());
        self::assertSame('Votre code de vérification est 424242. Il expire dans 300 secondes.', $mail->messages[0]->text);
        self::assertSame(2, $send->execute(['to' => 'ada@example.com', 'template' => 'email.otp', '--vars' => 'nope']));
        self::assertSame(1, $send->execute(['to' => '+1555', 'template' => 'sms.otp', '--vars' => '{"code":"1"}']), 'no SMS channel configured');
    }

    private static function polaris(MessagingPlugin $plugin, RecordingEventDispatcher $events, ?\Polaris\Contract\OtpMailerInterface $mailer = null): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: new FrozenClock(new DateTimeImmutable(self::NOW)),
            dispatcher: $events,
            mailer: $mailer,
            plugins: [new AuditPlugin(), $plugin],
        ));
    }
}
