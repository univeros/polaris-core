<?php

declare(strict_types=1);

namespace Polaris\Messaging\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Messaging\Schema;
use Polaris\Messaging\Template\ArrayTranslator;
use Polaris\Messaging\Template\PhpTemplateRenderer;
use Polaris\Messaging\Template\TemplateNotFoundException;
use Polaris\Messaging\Template\Templates;
use Polaris\Schema\Schema as Registry;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\FrozenClock;

#[CoversClass(ArrayTranslator::class)]
#[CoversClass(PhpTemplateRenderer::class)]
#[CoversClass(Templates::class)]
final class TemplateTest extends TestCase
{
    public function testEveryBundledTemplateRendersInEveryLocaleWithItsPlaceholders(): void
    {
        $renderer = new PhpTemplateRenderer(new ArrayTranslator(), new Templates(new InMemoryAdapter(), new FrozenClock(new DateTimeImmutable())));
        $vars = ['token' => 'tok', 'code' => '123456', 'ttl' => 300, 'link' => 'https://app.example/m', 'ip' => '203.0.113.7', 'user_agent' => 'UA', 'method' => 'reset', 'remaining' => 3];

        foreach (['en', 'es', 'de', 'fr', 'pt'] as $locale) {
            foreach (Templates::KEYS as $key) {
                $rendered = $renderer->render($key, $locale, $vars);
                self::assertStringNotContainsString('{', $rendered->text, "$locale $key leaves a placeholder");
                self::assertSame(str_starts_with($key, 'email.'), $rendered->subject !== null, "$locale $key subject");
            }
        }
        self::assertSame('Your verification code is 123456. It expires in 300 seconds.', $renderer->render('email.otp', 'en', $vars)->text);
        self::assertSame('Tu código de verificación es 123456.', $renderer->render('sms.otp', 'es', $vars)->text);
        self::assertStringContainsString('<strong>123456</strong>', (string) $renderer->render('email.otp', 'en', $vars)->html);
    }

    public function testAnUnknownLocaleFallsBackToTheDefaultAndAnUnknownKeyIsAnError(): void
    {
        $renderer = new PhpTemplateRenderer(new ArrayTranslator(), new Templates(new InMemoryAdapter(), new FrozenClock(new DateTimeImmutable())), 'es');

        self::assertSame('Tu código de verificación es 1.', $renderer->render('sms.otp', 'xx', ['code' => 1])->text);
        $this->expectException(TemplateNotFoundException::class);
        $renderer->render('sms.nope', 'en', []);
    }

    public function testOverridesWinInOrderAndTheHtmlIsEscaped(): void
    {
        Registry::register(...Schema::models());
        $database = new InMemoryAdapter();
        $templates = new Templates($database, new FrozenClock(new DateTimeImmutable('2026-09-11T10:00:00+00:00')), ['en' => ['email.otp' => ['subject' => 'Code {code}', 'text' => 'Instance says {code}', 'html' => '<b>{code}</b>']]]);
        $renderer = new PhpTemplateRenderer(new ArrayTranslator(['en' => ['sms.otp.text' => 'Host string {code}']]), $templates);

        self::assertSame('Host string 7', $renderer->render('sms.otp', 'en', ['code' => 7])->text, 'the host\'s strings win over the bundled ones');
        $instance = $renderer->render('email.otp', 'en', ['code' => '<1>']);
        self::assertSame(['Code <1>', 'Instance says <1>', '<b>&lt;1&gt;</b>'], [$instance->subject, $instance->text, $instance->html]);

        $templates->set('org-a', 'email.otp', 'en', 'Acme says {code}', 'Acme code');
        $organization = $renderer->render('email.otp', 'en', ['code' => 9], 'org-a');
        self::assertSame(['Acme code', 'Acme says 9', null], [$organization->subject, $organization->text, $organization->html]);
        self::assertSame('Instance says 9', $renderer->render('email.otp', 'en', ['code' => 9], 'org-b')->text, 'another organization gets the instance\'s');
        $templates->set('org-a', 'email.otp', 'en', 'Acme now says {code}');
        self::assertSame(1, $database->count(Schema::TEMPLATES, []), 'set replaces');
        self::assertSame('Acme now says 9', $renderer->render('email.otp', 'en', ['code' => 9], 'org-a')->text);
        self::assertTrue($templates->remove('org-a', 'email.otp', 'en'));
        self::assertFalse($templates->remove('org-a', 'email.otp', 'en'));
    }
}
