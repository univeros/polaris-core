<?php

declare(strict_types=1);

namespace Polaris\Messaging;

use LogicException;
use Override;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Cli\CommandProvider;
use Polaris\Contract\OtpMailerInterface;
use Polaris\Contract\SmsSenderInterface;
use Polaris\Messaging\Bridge\Mailer;
use Polaris\Messaging\Bridge\Sms;
use Polaris\Messaging\Channel\LogChannel;
use Polaris\Messaging\Console\SendCommand;
use Polaris\Messaging\Template\ArrayTranslator;
use Polaris\Messaging\Template\PhpTemplateRenderer;
use Polaris\Messaging\Template\TemplateRenderer;
use Polaris\Messaging\Template\Templates;
use Polaris\Messaging\Template\Translator;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;

/**
 * The messaging plugin: `new MessagingPlugin(channels: [...])` in `Config::$plugins`, after
 * `AuditPlugin`. It becomes core's mailer and SMS sender when the Config sets none, so the
 * verification, reset, invitation, code and security mails are rendered from its templates (the
 * bundled strings in five locales, the instance's overrides, an organization's) and sent through its
 * channels under its policy; every delivery is `messaging.sent` in the audit store.
 */
final class MessagingPlugin extends AbstractPlugin implements CommandProvider
{
    public const string ID = 'messaging';

    /**
     * @param list<Channel> $channels in order of preference; none means the log
     * @param array<string, array<string, array{subject?: string, text: string, html?: string}>> $templates instance overrides, locale => key => parts
     * @param array<string, array<string, string>> $strings translator strings, locale => id => string
     * @param array<string, array{int, int}> $caps template or kind => [limit, window seconds]
     * @param array<string, string> $fallback kind => kind
     */
    public function __construct(
        private readonly array $channels = [],
        private readonly string $locale = 'en',
        private readonly array $templates = [],
        private readonly array $strings = [],
        private readonly array $caps = ['*' => [5, 600]],
        private readonly array $fallback = [Message::SMS => Message::EMAIL],
        private readonly ?Suppressor $suppressor = null,
        private readonly ?Outbox $outbox = null,
        private readonly ?Translator $translator = null,
    ) {
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The messaging plugin is not registered.');
        }

        return $plugin;
    }

    #[Override]
    public function id(): string
    {
        return self::ID;
    }

    #[Override]
    public function schema(): array
    {
        return Schema::models();
    }

    #[Override]
    public function services(): array
    {
        return [
            Translator::class => fn(): Translator => $this->translator ?? new ArrayTranslator($this->strings),
            Templates::class => fn(Graph $graph): Templates => new Templates($graph->database(), $graph->clock(), $this->templates),
            TemplateRenderer::class => fn(Graph $graph): TemplateRenderer => new PhpTemplateRenderer($graph->get(Translator::class), $graph->get(Templates::class), $this->locale),
            MessagePolicy::class => fn(Graph $graph): MessagePolicy => new MessagePolicy($graph->rateStore(), $this->caps, $this->fallback, $this->suppressor),
            Outbox::class => fn(): Outbox => $this->outbox ?? new SyncOutbox(),
            Sender::class => fn(Graph $graph): Sender => new Sender(
                $this->channels === [] ? [new LogChannel($graph->logger(), $graph->clock())] : $this->channels,
                $graph->get(TemplateRenderer::class),
                $graph->get(MessagePolicy::class),
                $graph->get(Outbox::class),
                $graph->events(),
                $graph->logger(),
                $this->locale,
            ),
            OtpMailerInterface::class => static fn(Graph $graph): OtpMailerInterface => new Mailer($graph->get(Sender::class)),
            SmsSenderInterface::class => static fn(Graph $graph): SmsSenderInterface => new Sms($graph->get(Sender::class)),
        ];
    }

    #[Override]
    public function listeners(Graph $graph): array
    {
        self::catalog($graph);

        return [];
    }

    #[Override]
    public function commands(Graph $graph): array
    {
        return [new SendCommand(static fn(): Graph => $graph)];
    }

    /**
     * `messaging.sent` joins the audit catalog: the audit plugin must be registered.
     */
    public static function catalog(Graph $graph): Catalog
    {
        AuditPlugin::of($graph);
        $catalog = $graph->get(Catalog::class);
        $catalog->extend([MessageSent::NAME => 'A message was sent (channel, template, recipient hash, provider id)']);

        return $catalog;
    }
}
