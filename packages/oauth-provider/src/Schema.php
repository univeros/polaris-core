<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use Polaris\OAuth\Model\CibaRequest;
use Polaris\OAuth\Model\Client;
use Polaris\OAuth\Model\Code;
use Polaris\OAuth\Model\Consent;
use Polaris\OAuth\Model\DeviceCode;
use Polaris\OAuth\Model\Token;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

/**
 * The tables the plugin owns: the registered clients, the users' consents, the authorization codes,
 * the issued tokens (every access token by `jti`, every refresh token by keyed hash, in rotation
 * families), the device-flow codes and the backchannel (CIBA) requests.
 */
final class Schema
{
    public const string CLIENTS = 'polaris_oauth_client';
    public const string CONSENTS = 'polaris_oauth_consent';
    public const string CODES = 'polaris_oauth_code';
    public const string TOKENS = 'polaris_oauth_token';
    public const string DEVICE_CODES = 'polaris_oauth_device_code';
    public const string CIBA_REQUESTS = 'polaris_oauth_ciba_request';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::CLIENTS, Client::class, [
                Field::string('id', 36)->primary(),
                Field::string('clientId', 255),
                Field::string('organizationId', 36)->nullable(),
                Field::string('name', 160),
                Field::string('type', 16),
                Field::string('secretHash', 128)->nullable(),
                Field::json('redirectUris'),
                Field::json('grantTypes'),
                Field::json('scopes'),
                Field::string('tokenEndpointAuthMethod', 32),
                Field::json('jwks')->nullable(),
                Field::string('jwksUri', 2048)->nullable(),
                Field::bool('dpopBound')->default(false),
                Field::bool('trusted')->default(false),
                Field::string('logoUri', 2048)->nullable(),
                Field::string('clientUri', 2048)->nullable(),
                Field::string('policyUri', 2048)->nullable(),
                Field::string('tosUri', 2048)->nullable(),
                Field::string('createdBy', 36)->nullable(),
                Field::datetime('disabledAt')->nullable(),
                Field::datetime('createdAt'),
                Field::datetime('updatedAt'),
            ])->unique(['client_id'], 'polaris_oauth_client_id_unique')
                ->index(['organization_id'], 'polaris_oauth_client_org_index'),
            Model::table(self::CONSENTS, Consent::class, [
                Field::string('id', 36)->primary(),
                Field::string('userId', 36),
                Field::string('clientId', 255),
                Field::string('organizationId', 36)->nullable(),
                Field::json('scopes'),
                Field::datetime('grantedAt'),
                Field::datetime('updatedAt'),
            ])->unique(['user_id', 'client_id'], 'polaris_oauth_consent_unique'),
            Model::table(self::CODES, Code::class, [
                Field::string('id', 36)->primary(),
                Field::string('codeHash', 128),
                Field::string('clientId', 255),
                Field::string('userId', 36),
                Field::string('organizationId', 36)->nullable(),
                Field::json('scopes'),
                Field::string('redirectUri', 2048),
                Field::string('codeChallenge', 128),
                Field::string('nonce', 255)->nullable(),
                Field::string('resource', 2048)->nullable(),
                Field::string('dpopJkt', 128)->nullable(),
                Field::int('authTime')->nullable(),
                Field::datetime('expiresAt'),
                Field::datetime('usedAt')->nullable(),
                Field::datetime('createdAt'),
            ])->unique(['code_hash'], 'polaris_oauth_code_hash_unique'),
            Model::table(self::TOKENS, Token::class, [
                Field::string('id', 36)->primary(),
                Field::string('kind', 8),
                Field::string('tokenHash', 128)->nullable(),
                Field::string('clientId', 255),
                Field::string('userId', 36)->nullable(),
                Field::string('organizationId', 36)->nullable(),
                Field::json('scopes'),
                Field::string('familyId', 36)->nullable(),
                Field::string('resource', 2048)->nullable(),
                Field::string('dpopJkt', 128)->nullable(),
                Field::json('actor')->nullable(),
                Field::int('authTime')->nullable(),
                Field::datetime('expiresAt'),
                Field::datetime('revokedAt')->nullable(),
                Field::datetime('createdAt'),
            ])->unique(['token_hash'], 'polaris_oauth_token_hash_unique')
                ->index(['user_id', 'client_id'], 'polaris_oauth_token_user_index')
                ->index(['family_id'], 'polaris_oauth_token_family_index'),
            Model::table(self::DEVICE_CODES, DeviceCode::class, [
                Field::string('id', 36)->primary(),
                Field::string('deviceCodeHash', 128),
                Field::string('userCode', 16),
                Field::string('clientId', 255),
                Field::json('scopes'),
                Field::string('resource', 2048)->nullable(),
                Field::string('status', 16),
                Field::string('userId', 36)->nullable(),
                Field::string('organizationId', 36)->nullable(),
                Field::int('authTime')->nullable(),
                Field::datetime('lastPolledAt')->nullable(),
                Field::datetime('expiresAt'),
                Field::datetime('createdAt'),
            ])->unique(['device_code_hash'], 'polaris_oauth_device_code_hash_unique')
                ->unique(['user_code'], 'polaris_oauth_device_user_code_unique'),
            Model::table(self::CIBA_REQUESTS, CibaRequest::class, [
                Field::string('id', 36)->primary(),
                Field::string('clientId', 255),
                Field::string('userId', 36),
                Field::string('organizationId', 36)->nullable(),
                Field::json('scopes'),
                Field::string('bindingMessage', 160)->nullable(),
                Field::string('resource', 2048)->nullable(),
                Field::string('status', 16),
                Field::int('authTime')->nullable(),
                Field::datetime('lastPolledAt')->nullable(),
                Field::datetime('expiresAt'),
                Field::datetime('createdAt'),
            ])->index(['user_id', 'status'], 'polaris_oauth_ciba_user_index'),
        ];
    }
}
