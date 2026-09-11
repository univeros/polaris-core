<?php

declare(strict_types=1);

namespace Polaris\Messaging\Tests;

use DateTimeImmutable;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\StreamFactory;
use PHPMailer\PHPMailer\PHPMailer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Messaging\Channel\ArrayChannel;
use Polaris\Messaging\Channel\LogChannel;
use Polaris\Messaging\Channel\PhpMailerChannel;
use Polaris\Messaging\Channel\SymfonyMailerChannel;
use Polaris\Messaging\Channel\TwilioSmsChannel;
use Polaris\Messaging\Channel\VonageSmsChannel;
use Polaris\Messaging\DeliveryException;
use Polaris\Messaging\Message;
use Polaris\Messaging\Tests\Support\FakeHttpClient;
use Polaris\Tests\Support\FrozenClock;
use Polaris\Tests\Support\RecordingLogger;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\RawMessage;

#[CoversClass(TwilioSmsChannel::class)]
#[CoversClass(VonageSmsChannel::class)]
#[CoversClass(SymfonyMailerChannel::class)]
#[CoversClass(PhpMailerChannel::class)]
#[CoversClass(LogChannel::class)]
#[CoversClass(ArrayChannel::class)]
final class ChannelsTest extends TestCase
{
    private const string NOW = '2026-09-11T10:00:00+00:00';

    public function testTwilioPostsAFormAndReadsTheSid(): void
    {
        $http = new FakeHttpClient(201, '{"sid":"SM123"}');
        $channel = new TwilioSmsChannel($http, new RequestFactory(), new StreamFactory(), new FrozenClock(new DateTimeImmutable(self::NOW)), 'AC1', 'secret', '+15550000000');

        self::assertTrue($channel->supports(Message::SMS));
        self::assertFalse($channel->supports(Message::EMAIL));
        $receipt = $channel->send(new Message(Message::SMS, '+15551234567', 'sms.otp', 'Your code is 1.'));
        self::assertSame(['twilio', 'SM123', self::NOW], [$receipt->channel, $receipt->providerId, $receipt->sentAt->format(DATE_ATOM)]);
        $request = $http->requests[0];
        self::assertSame('https://api.twilio.com/2010-04-01/Accounts/AC1/Messages.json', (string) $request->getUri());
        self::assertSame('Basic ' . base64_encode('AC1:secret'), $request->getHeaderLine('Authorization'));
        parse_str((string) $request->getBody(), $form);
        self::assertSame(['To' => '+15551234567', 'From' => '+15550000000', 'Body' => 'Your code is 1.'], $form);
    }

    public function testVonagePostsJsonAndAFailureIsADeliveryException(): void
    {
        $http = new FakeHttpClient(200, '{"messages":[{"message-id":"0A0000"}]}');
        $channel = new VonageSmsChannel($http, new RequestFactory(), new StreamFactory(), new FrozenClock(new DateTimeImmutable(self::NOW)), 'key', 'secret', 'Polaris');
        $receipt = $channel->send(new Message(Message::SMS, '+15551234567', 'sms.otp', 'Your code is 1.'));
        self::assertSame('0A0000', $receipt->providerId);
        self::assertSame('{"api_key":"key","api_secret":"secret","from":"Polaris","to":"+15551234567","text":"Your code is 1."}', (string) $http->requests[0]->getBody());

        $down = new VonageSmsChannel(new FakeHttpClient(503, ''), new RequestFactory(), new StreamFactory(), new FrozenClock(new DateTimeImmutable(self::NOW)), 'key', 'secret', 'Polaris');
        $this->expectException(DeliveryException::class);
        $this->expectExceptionMessage('HTTP 503');
        $down->send(new Message(Message::SMS, '+15551234567', 'sms.otp', 'x'));
    }

    public function testSymfonyMailerSendsSubjectTextAndHtml(): void
    {
        $mailer = new class implements MailerInterface {
            /** @var list<RawMessage> */
            public array $sent = [];

            public function send(RawMessage $message, ?Envelope $envelope = null): void
            {
                $this->sent[] = $message;
            }
        };
        $channel = new SymfonyMailerChannel($mailer, 'noreply@example.test', new FrozenClock(new DateTimeImmutable(self::NOW)));

        self::assertTrue($channel->supports(Message::EMAIL));
        self::assertFalse($channel->supports(Message::SMS));
        $receipt = $channel->send(new Message(Message::EMAIL, 'ada@example.com', 'email.otp', 'Code 1', 'Your code', '<b>1</b>'));
        self::assertSame('symfony_mailer', $receipt->channel);
        $email = $mailer->sent[0];
        self::assertInstanceOf(Email::class, $email);
        self::assertSame(['Your code', 'Code 1', '<b>1</b>', 'ada@example.com', 'noreply@example.test'], [$email->getSubject(), $email->getTextBody(), $email->getHtmlBody(), $email->getTo()[0]->getAddress(), $email->getFrom()[0]->getAddress()]);
    }

    public function testPhpMailerSendsThroughAClone(): void
    {
        $mailer = new class extends PHPMailer {
            public static int $sends = 0;
            public bool $shouldFail = false;

            public function send(): bool
            {
                ++self::$sends;
                if ($this->shouldFail) {
                    $this->ErrorInfo = 'SMTP down';

                    return false;
                }

                return true;
            }
        };
        $mailer->setFrom('noreply@example.test');
        $channel = new PhpMailerChannel($mailer, new FrozenClock(new DateTimeImmutable(self::NOW)));

        $receipt = $channel->send(new Message(Message::EMAIL, 'ada@example.com', 'email.otp', 'Code 1', 'Your code', '<b>1</b>'));
        self::assertSame('phpmailer', $receipt->channel);
        self::assertSame(1, $mailer::$sends);
        self::assertSame([], $mailer->getToAddresses(), 'the configured instance is untouched: the send used a clone');

        $mailer->shouldFail = true;
        $this->expectException(DeliveryException::class);
        $this->expectExceptionMessage('SMTP down');
        $channel->send(new Message(Message::EMAIL, 'ada@example.com', 'email.otp', 'Code 1', 'Your code'));
    }

    public function testTheLogAndArrayChannels(): void
    {
        $logger = new RecordingLogger();
        $log = new LogChannel($logger, new FrozenClock(new DateTimeImmutable(self::NOW)));
        self::assertSame('log', $log->send(new Message(Message::SMS, '+1', 'sms.otp', 'Code 1'))->channel);
        self::assertCount(1, $logger->records);

        $array = new ArrayChannel('mail', [Message::EMAIL]);
        self::assertFalse($array->supports(Message::SMS));
        self::assertSame('mail-1', $array->send(new Message(Message::EMAIL, 'a@b.c', 'email.otp', 'x'))->providerId);
        $array->failing = true;
        $this->expectException(DeliveryException::class);
        $array->send(new Message(Message::EMAIL, 'a@b.c', 'email.otp', 'x'));
    }
}
