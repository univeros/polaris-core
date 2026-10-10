#!/usr/bin/env php
<?php

declare(strict_types=1);

/*
 * The agent steps of the walkthrough, through polaris/agent (the PHP agent SDK): discover the server,
 * enrol an agent with its own key through a host's enrolment token, request the demo's low-risk
 * capability (approved by policy), execute it twice with signed request JWTs, and verify the receipt
 * chain the owner lists, locally against the server's JWKS. Prints one line per step as walkthrough.sh
 * does; exits non-zero on the first failure.
 *
 * Usage: bin/agent-walkthrough.php <url> <enrollment token> <owner access token>
 */

use Polaris\Agent\AgentException;
use Polaris\Agent\AgentKey;
use Polaris\Agent\Http\StreamClient;
use Polaris\Agent\PolarisAgent;
use Slim\Psr7\Factory\RequestFactory;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\StreamFactory;

require dirname(__DIR__) . '/vendor/autoload.php';

[$url, $enrollmentToken, $owner] = [$argv[1] ?? '', $argv[2] ?? '', $argv[3] ?? ''];
if ($url === '' || $enrollmentToken === '' || $owner === '') {
    fwrite(STDERR, "usage: bin/agent-walkthrough.php <url> <enrollment token> <owner access token>\n");
    exit(2);
}
$step = static fn(string $label, int|string $status): int => printf("%-52s %s\n", $label, $status);
$fail = static function (string $message): never {
    fwrite(STDERR, $message . "\n");
    exit(1);
};
$client = new StreamClient(new ResponseFactory(), new StreamFactory());
$requests = new RequestFactory();
$streams = new StreamFactory();

try {
    $sdk = PolarisAgent::create($url, $client, $requests, $streams, AgentKey::generate('EdDSA'));
    $step('22. GET /.well-known/agent-configuration (polaris/agent)', 200);

    $enrolled = $sdk->enroll($enrollmentToken, ['name' => 'Walkthrough agent', 'mode' => 'delegated']);
    $step('23. POST /agents/enroll (an EdDSA key of its own)', 201);
    $agent = $sdk->bound((string) $enrolled['id']);

    $asked = $agent->requestGrants(['demo.echo'], ['reason' => 'The walkthrough']);
    $grant = $asked['agent_capability_grants'][0] ?? [];
    ($grant['status'] ?? null) === 'active' && ($grant['approved_via'] ?? null) === 'auto' || $fail('demo.echo was not approved by policy: ' . json_encode($asked));
    $step('24. POST /agents/grants/request (low risk: auto-approved)', 200);

    $first = $agent->execute('demo.echo', ['message' => 'hello']);
    ($first['data']['echo']['message'] ?? null) === 'hello' || $fail('the handler did not echo: ' . json_encode($first));
    $second = $agent->execute('demo.echo', ['message' => 'again']);
    ($second['receipt']['seq'] ?? null) === 2 || $fail('the second receipt is not seq 2: ' . json_encode($second));
    $step('25. POST /agents/execute x2 (signed request JWTs)', 200);

    // The chain, as the owner lists it; verified locally: the hash, core's signature, the link.
    $listed = $client->sendRequest($requests->createRequest('GET', $sdk->configuration->mount . '/agents/' . $enrolled['id'] . '/receipts')->withHeader('Authorization', 'Bearer ' . $owner)->withHeader('Accept', 'application/json'));
    $chain = json_decode((string) $listed->getBody(), true)['data'] ?? null;
    $listed->getStatusCode() === 200 && is_array($chain) && count($chain) === 2 || $fail('the owner could not list two receipts: ' . $listed->getBody());
    $step('26. GET /agents/{id}/receipts (the owner)', $listed->getStatusCode());
    $one = $agent->verifyReceipt($chain[0]);
    $two = $agent->verifyReceipt($chain[1], $chain[0]);
    $one['valid'] && $two['valid'] || $fail('a receipt did not verify: ' . json_encode([$one, $two]));
    $step('27. receipts verified against /auth/.well-known/jwks.json', 'ok');
    echo 'AGENT: enrolled ' . $enrolled['id'] . ' through the host, executed demo.echo twice, receipt chain ' . substr((string) $chain[1]['hash'], 0, 12) . "... verified\n";
} catch (AgentException $exception) {
    $fail($exception->getMessage() . ($exception->problem === null ? '' : ' ' . json_encode($exception->problem)));
}
