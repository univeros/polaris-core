<?php

declare(strict_types=1);

namespace Polaris\Agent\Tests;

use PHPUnit\Framework\TestCase;
use Polaris\Agent\Receipts;
use Polaris\Agent\Tests\Support\Fixtures;
use Polaris\Agents\Receipts as ServerReceipts;

use function hash;

final class ReceiptsTest extends TestCase
{
    public function testItCanonicalisesAndHashesAsTheServerDoes(): void
    {
        $receipt = Fixtures::receipt(['capability' => 'café/échec', 'constraints' => ['b' => [2, 1], 'a' => '/']]);
        self::assertSame('{"a":null,"b":[{"a":"/","z":1}],"seq":1}', Receipts::canonical(['seq' => 1, 'b' => [['z' => 1, 'a' => '/']], 'a' => null]));
        self::assertSame(ServerReceipts::canonical(['seq' => 1, 'b' => [['z' => 1, 'a' => '/']], 'a' => null]), Receipts::canonical(['seq' => 1, 'b' => [['z' => 1, 'a' => '/']], 'a' => null]));
        $fields = [];
        foreach (Receipts::HASHED as $field) {
            $fields[$field] = $receipt[$field];
        }
        self::assertSame(hash('sha256', ServerReceipts::canonical($fields)), Receipts::hashOf($receipt));
        self::assertSame('9b5f1f690cca6b3b9dd055a71d13ebd6f8a0a7efcd529befc560383e477f836d', Receipts::hashOf($receipt), 'the vector the TypeScript SDK checks too');
    }

    public function testItVerifiesAChainAgainstTheJwksAndDetectsATamperedReceipt(): void
    {
        ['pem' => $pem, 'jwks' => $jwks] = Fixtures::serverKey();
        $first = Fixtures::receipt();
        $first['hash'] = Receipts::hashOf($first);
        $first['signature'] = Fixtures::signReceipt($pem, $first, $first['hash']);
        self::assertSame(['valid' => true, 'checks' => ['hash' => true, 'signature' => true, 'chain' => true]], Receipts::verify($first, $jwks));

        $second = Fixtures::receipt(['id' => 'r2', 'seq' => 2, 'prev_hash' => $first['hash'], 'budget_before' => 99, 'budget_after' => 98]);
        $second['hash'] = Receipts::hashOf($second);
        $second['signature'] = Fixtures::signReceipt($pem, $second, $second['hash']);
        self::assertSame(['valid' => true, 'checks' => ['hash' => true, 'signature' => true, 'chain' => true]], Receipts::verify($second, $jwks, $first));
        self::assertTrue(Receipts::verify($second, $jwks)['checks']['chain'], 'without the previous receipt only the link\'s presence is checked');

        $tampered = [...$first, 'budget_after' => 1];
        self::assertSame(['valid' => false, 'checks' => ['hash' => false, 'signature' => false, 'chain' => true]], Receipts::verify($tampered, $jwks));
        self::assertSame(['hash' => true, 'signature' => true, 'chain' => false], Receipts::verify($second, $jwks, $tampered)['checks'], 'the successor no longer links to it');

        ['pem' => $forger] = Fixtures::serverKey();
        self::assertFalse(Receipts::verify([...$first, 'signature' => Fixtures::signReceipt($forger, $first, $first['hash'])], $jwks)['checks']['signature'], 'another key');
        self::assertFalse(Receipts::verify([...$first, 'signature' => Fixtures::signReceipt($pem, $first, $first['hash'], 'unknown')], $jwks)['checks']['signature'], 'an unknown kid');
        self::assertFalse(Receipts::verify([...$second, 'signature' => $first['signature']], $jwks, $first)['checks']['signature'], 'a signature of another receipt');
        self::assertSame(['hash' => false, 'signature' => false, 'chain' => false], Receipts::verify([...$first, 'prev_hash' => 'x'], $jwks)['checks'], 'a first receipt claiming a predecessor');
    }
}
