# polaris/messaging

Messaging for [Polaris for PHP](https://github.com/univeros/polaris-core): the verification, reset,
invitation, one-time-code and security messages rendered from templates you can override per instance and
per organization, translated (en, es, de, fr, pt bundled), rate-limited per recipient, sent through the
channel you choose (Symfony Mailer, PHPMailer, Twilio, Vonage, a log, an array in tests), every send
recorded in the audit store without its body.

```sh
composer require polaris/messaging
```

```php
use Polaris\Audit\AuditPlugin;
use Polaris\Messaging\Channel\SymfonyMailerChannel;
use Polaris\Messaging\Channel\TwilioSmsChannel;
use Polaris\Messaging\MessagingPlugin;

$polaris = Polaris::create(new Config(
    ...,                                               // leave `mailer` and `sms` unset: the plugin provides them
    plugins: [new AuditPlugin(), new MessagingPlugin(
        channels: [new SymfonyMailerChannel($mailer, 'noreply@example.com', $clock), new TwilioSmsChannel($psr18, $psr17, $psr17, $clock, $sid, $token, $from)],
        locale: 'en',
        templates: ['en' => ['email.verify' => ['subject' => 'Welcome to Acme', 'text' => 'Verify at https://acme.example/verify/{token}']]],
        caps: ['*' => [5, 600], 'sms.otp' => [3, 600]],   // per recipient and template: [limit, window seconds]
    )],
));
```

`polaris/audit` is required and registered too: every delivery is a `messaging.sent` event. In Laravel,
Symfony and Yii the instance goes in the adapter's `plugins` configuration with the adapter's `mailer` and
`sms` left unset (`log`), so the plugin takes over both ports.

## How it reaches core

Core sends through two ports, `OtpMailerInterface` and `SmsSenderInterface`. When the configuration leaves
them unset, the graph takes a plugin's implementation: this plugin's `Bridge\Mailer` renders core's
templates (`verify_email`, `password_reset`, `org_invite`, `otp_code`, `account_locked`,
`password_changed`, `mfa_enrolled`, `mfa_factor_removed`, `recovery_codes_regenerated`,
`recovery_code_used`) from the keys below and sends them as email; `Bridge\Sms` sends core's code message
as `sms.otp`. A host that keeps its own `mailer` keeps it; the plugin's `Sender` is still there for the
application's own messages:

```php
$graph->get(Sender::class)->send('email', $user->email, 'email.new_device', ['ip' => $ip, 'user_agent' => $ua], locale: 'es', organizationId: $orgId);
```

## Templates and translations

Keys: `email.verify`, `email.reset_password`, `email.magic_link`, `email.otp`, `email.invite`,
`email.new_device`, `email.password_changed`, `email.account_locked`, `email.mfa_enrolled`,
`email.mfa_factor_removed`, `email.recovery_codes_regenerated`, `email.recovery_code_used`, `sms.otp`,
`sms.new_device`. Each is a subject (email), a text and an optional HTML with `{placeholders}`
(`{token}`, `{code}`, `{ttl}`, `{link}`, `{ip}`, `{user_agent}`, `{method}`, `{remaining}`), escaped in the
HTML. Resolution: the organization's override (`polaris_messaging_template`, written with
`Templates::set()`), then the instance's (`templates:`), then the bundled strings of the locale, then of the
default locale. Strings come from a `Translator`: the bundled `ArrayTranslator` (`resources/translations`)
takes the host's additions (`strings:`), or the host plugs its own.

## Policy and channels

`MessagePolicy`: a cap per recipient and template (or kind, or `*`) through core's rate store; a fallback
kind (`sms` → `email`) used when no channel of the first kind delivered and the send named an alternative
recipient; quiet mode through a `Suppressor` (`polaris/sentinel` implements it) that drops non-essential
messages. Channels are tried in order for the message's kind; a channel throws `DeliveryException` and the
next is tried; a refused or undelivered message is logged and never breaks the operation that asked for
it. `Outbox` is the queue seam (`SyncOutbox` by default; a host's queue driver takes sends off the request
path). `polaris messaging:send <to> <template> --vars='{"code":"123456"}'` checks a channel from the console.

## License

MIT. Polaris for PHP is created and maintained by [2am.tech](https://2am.tech).
