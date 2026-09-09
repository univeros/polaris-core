<?php

declare(strict_types=1);

namespace Polaris\Http;

/**
 * Names of the request attributes adapters set for the endpoints. `ROUTE` carries the matched
 * {@see \Polaris\Http\Manifest\EndpointSpec} once routing ran. Adapters (PSR-15, framework
 * bridges) translate their own attribute names to these before an endpoint runs.
 */
final class Attributes
{
    public const string TOKEN = 'polaris.token';
    public const string MFA_TICKET = 'polaris.mfa_ticket';
    public const string AUTHORITY = 'polaris.authority';
    public const string IP_ADDRESS = 'polaris.ip_address';
    public const string USER_AGENT = 'polaris.user_agent';
    public const string ROUTE = 'polaris.route';
    public const string ROUTE_PARAMS = 'polaris.route_params';

    private function __construct()
    {
    }
}
