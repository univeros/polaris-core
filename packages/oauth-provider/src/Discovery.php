<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use Polaris\Config\AuthConfig;

/**
 * The server's metadata: OpenID Connect Discovery (`/.well-known/openid-configuration`) and RFC 8414
 * (`/.well-known/oauth-authorization-server`), both saying exactly what is enabled.
 */
final class Discovery
{
    public function __construct(
        private readonly Settings $settings,
        private readonly Scopes $scopes,
        private readonly AuthConfig $auth,
        private readonly string $baseUrl,
    ) {
    }

    /**
     * The absolute URL of one of the plugin's routes (`/oauth2/token`).
     */
    public function url(string $path): string
    {
        return $this->baseUrl . $path;
    }

    public function issuer(): string
    {
        return $this->auth->issuer;
    }

    /**
     * @return array<string, mixed>
     */
    public function authorizationServer(): array
    {
        $grants = [Clients::GRANT_CODE, Clients::GRANT_REFRESH, Clients::GRANT_CLIENT, Clients::GRANT_CIBA, Clients::GRANT_EXCHANGE];
        if ($this->settings->deviceUrl !== null) {
            $grants[] = Clients::GRANT_DEVICE;
        }
        $document = [
            'issuer' => $this->auth->issuer,
            'authorization_endpoint' => $this->baseUrl . '/oauth2/authorize',
            'token_endpoint' => $this->baseUrl . '/oauth2/token',
            'jwks_uri' => $this->baseUrl . '/auth/.well-known/jwks.json',
            'revocation_endpoint' => $this->baseUrl . '/oauth2/revoke',
            'introspection_endpoint' => $this->baseUrl . '/oauth2/introspect',
            'backchannel_authentication_endpoint' => $this->baseUrl . '/oauth2/ciba',
            'scopes_supported' => $this->scopes->names(),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => $grants,
            'token_endpoint_auth_methods_supported' => Clients::AUTH_METHODS,
            'token_endpoint_auth_signing_alg_values_supported' => ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'],
            'revocation_endpoint_auth_methods_supported' => Clients::AUTH_METHODS,
            'introspection_endpoint_auth_methods_supported' => Clients::AUTH_METHODS,
            'code_challenge_methods_supported' => ['S256'],
            'backchannel_token_delivery_modes_supported' => ['poll'],
            'backchannel_user_code_parameter_supported' => false,
            'authorization_response_iss_parameter_supported' => true,
            'client_id_metadata_document_supported' => $this->settings->clientIdMetadata,
        ];
        if ($this->settings->deviceUrl !== null) {
            $document['device_authorization_endpoint'] = $this->baseUrl . '/oauth2/device/code';
        }
        if ($this->settings->dynamicRegistration) {
            $document['registration_endpoint'] = $this->baseUrl . '/oauth2/register';
        }
        if ($this->settings->dpop !== Settings::DPOP_OFF) {
            $document['dpop_signing_alg_values_supported'] = ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'EdDSA'];
        }

        return $document;
    }

    /**
     * @return array<string, mixed>
     */
    public function openId(): array
    {
        return [
            ...$this->authorizationServer(),
            'userinfo_endpoint' => $this->baseUrl . '/oauth2/userinfo',
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => [$this->auth->accessToken->signer],
            'claims_supported' => ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'email', 'email_verified', 'name', 'updated_at', 'org'],
            'claims_parameter_supported' => false,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
        ];
    }
}
