<?php

declare(strict_types=1);

namespace Polaris\Social\Provider;

use Polaris\Social\SocialException;

use function array_key_first;
use function in_array;
use function is_array;
use function is_string;
use function sprintf;
use function str_replace;

/**
 * The known providers as data: Google, Apple, Microsoft, GitHub, GitLab, Discord, Facebook, X, LinkedIn,
 * Slack, Twitch, Spotify, Zoom, Notion, Dropbox, Reddit, Kick, TikTok, Hugging Face. Each maps its
 * profile onto {@see Profile}; the subject is the provider's stable account id, the email the one the
 * provider reports, verified only when the provider says so (or, for a provider that only ever hands
 * out verified addresses, always).
 */
final class Catalog
{
    public const array IDS = ['google', 'apple', 'microsoft', 'github', 'gitlab', 'discord', 'facebook', 'x', 'linkedin', 'slack', 'twitch', 'spotify', 'zoom', 'notion', 'dropbox', 'reddit', 'kick', 'tiktok', 'huggingface'];

    /**
     * @param array<string, mixed> $options provider-specific: Microsoft's `tenant` (`common` by default)
     * @throws SocialException an unknown provider
     */
    public static function definition(string $id, array $options = []): Definition
    {
        $tenant = is_string($options['tenant'] ?? null) && $options['tenant'] !== '' ? $options['tenant'] : 'common';

        return match ($id) {
            'google' => new Definition('google', 'Google', 'https://accounts.google.com/o/oauth2/v2/auth', 'https://oauth2.googleapis.com/token', 'https://openidconnect.googleapis.com/v1/userinfo', ['openid', 'email', 'profile'], static fn(array $data): Profile => self::oidcProfile($data), issuer: 'https://accounts.google.com', authorizationParams: ['access_type' => 'offline', 'prompt' => 'select_account']),
            'apple' => new Definition('apple', 'Apple', 'https://appleid.apple.com/auth/authorize', 'https://appleid.apple.com/auth/token', null, ['name', 'email'], static fn(array $data): Profile => self::oidcProfile($data), pkce: false, issuer: 'https://appleid.apple.com', jwksUri: 'https://appleid.apple.com/auth/keys', formPost: true),
            'microsoft' => new Definition('microsoft', 'Microsoft', sprintf('https://login.microsoftonline.com/%s/oauth2/v2.0/authorize', $tenant), sprintf('https://login.microsoftonline.com/%s/oauth2/v2.0/token', $tenant), 'https://graph.microsoft.com/oidc/userinfo', ['openid', 'email', 'profile', 'offline_access'], static fn(array $data): Profile => self::oidcProfile($data), issuer: in_array($tenant, ['common', 'organizations', 'consumers'], true) ? '#^https://login\.microsoftonline\.com/[0-9a-f-]{36}/v2\.0$#' : sprintf('https://login.microsoftonline.com/%s/v2.0', $tenant), jwksUri: sprintf('https://login.microsoftonline.com/%s/discovery/v2.0/keys', $tenant)),
            'github' => new Definition('github', 'GitHub', 'https://github.com/login/oauth/authorize', 'https://github.com/login/oauth/access_token', 'https://api.github.com/user', ['read:user', 'user:email'], static fn(array $data): Profile => new Profile((string) ($data['id'] ?? ''), self::text($data['email'] ?? null), (bool) ($data['email_verified'] ?? false), self::text($data['name'] ?? null) ?? self::text($data['login'] ?? null), ['login' => $data['login'] ?? null, 'picture' => $data['avatar_url'] ?? null]), pkce: false, userinfoHeaders: ['Accept' => 'application/vnd.github+json']),
            'gitlab' => new Definition('gitlab', 'GitLab', 'https://gitlab.com/oauth/authorize', 'https://gitlab.com/oauth/token', 'https://gitlab.com/oauth/userinfo', ['openid', 'email', 'profile'], static fn(array $data): Profile => self::oidcProfile($data), issuer: 'https://gitlab.com'),
            'discord' => new Definition('discord', 'Discord', 'https://discord.com/oauth2/authorize', 'https://discord.com/api/oauth2/token', 'https://discord.com/api/users/@me', ['identify', 'email'], static fn(array $data): Profile => new Profile((string) ($data['id'] ?? ''), self::text($data['email'] ?? null), (bool) ($data['verified'] ?? false), self::text($data['global_name'] ?? null) ?? self::text($data['username'] ?? null), ['username' => $data['username'] ?? null]), pkce: false),
            'facebook' => new Definition('facebook', 'Facebook', 'https://www.facebook.com/v19.0/dialog/oauth', 'https://graph.facebook.com/v19.0/oauth/access_token', 'https://graph.facebook.com/me?fields=id,name,email,picture', ['email', 'public_profile'], static fn(array $data): Profile => new Profile((string) ($data['id'] ?? ''), self::text($data['email'] ?? null), self::text($data['email'] ?? null) !== null, self::text($data['name'] ?? null), ['picture' => $data['picture']['data']['url'] ?? null]), pkce: false, scopeSeparator: ','),
            'x' => new Definition('x', 'X', 'https://x.com/i/oauth2/authorize', 'https://api.x.com/2/oauth2/token', 'https://api.x.com/2/users/me?user.fields=profile_image_url,confirmed_email', ['users.read', 'tweet.read', 'offline.access'], static fn(array $data): Profile => new Profile((string) ($data['data']['id'] ?? ''), self::text($data['data']['confirmed_email'] ?? null), self::text($data['data']['confirmed_email'] ?? null) !== null, self::text($data['data']['name'] ?? null), ['username' => $data['data']['username'] ?? null, 'picture' => $data['data']['profile_image_url'] ?? null]), tokenAuth: Definition::AUTH_BASIC),
            'linkedin' => new Definition('linkedin', 'LinkedIn', 'https://www.linkedin.com/oauth/v2/authorization', 'https://www.linkedin.com/oauth/v2/accessToken', 'https://api.linkedin.com/v2/userinfo', ['openid', 'profile', 'email'], static fn(array $data): Profile => self::oidcProfile($data), pkce: false, issuer: 'https://www.linkedin.com/oauth'),
            'slack' => new Definition('slack', 'Slack', 'https://slack.com/openid/connect/authorize', 'https://slack.com/api/openid.connect.token', 'https://slack.com/api/openid.connect.userInfo', ['openid', 'email', 'profile'], static fn(array $data): Profile => self::oidcProfile($data), pkce: false, issuer: 'https://slack.com'),
            'twitch' => new Definition('twitch', 'Twitch', 'https://id.twitch.tv/oauth2/authorize', 'https://id.twitch.tv/oauth2/token', 'https://id.twitch.tv/oauth2/userinfo', ['openid', 'user:read:email'], static fn(array $data): Profile => self::oidcProfile($data), pkce: false, issuer: 'https://id.twitch.tv/oauth2', authorizationParams: ['claims' => '{"userinfo":{"email":null,"email_verified":null,"preferred_username":null,"picture":null}}']),
            'spotify' => new Definition('spotify', 'Spotify', 'https://accounts.spotify.com/authorize', 'https://accounts.spotify.com/api/token', 'https://api.spotify.com/v1/me', ['user-read-email', 'user-read-private'], static fn(array $data): Profile => new Profile((string) ($data['id'] ?? ''), self::text($data['email'] ?? null), false, self::text($data['display_name'] ?? null), ['picture' => $data['images'][0]['url'] ?? null])),
            'zoom' => new Definition('zoom', 'Zoom', 'https://zoom.us/oauth/authorize', 'https://zoom.us/oauth/token', 'https://api.zoom.us/v2/users/me', ['user:read:user'], static fn(array $data): Profile => new Profile((string) ($data['id'] ?? ''), self::text($data['email'] ?? null), (bool) ($data['verified'] ?? false), self::text($data['display_name'] ?? null), ['picture' => $data['pic_url'] ?? null]), tokenAuth: Definition::AUTH_BASIC),
            'notion' => new Definition('notion', 'Notion', 'https://api.notion.com/v1/oauth/authorize', 'https://api.notion.com/v1/oauth/token', null, [], static fn(array $data): Profile => new Profile((string) ($data['owner']['user']['id'] ?? ''), self::text($data['owner']['user']['person']['email'] ?? null), self::text($data['owner']['user']['person']['email'] ?? null) !== null, self::text($data['owner']['user']['name'] ?? null), ['workspace' => $data['workspace_name'] ?? null, 'picture' => $data['owner']['user']['avatar_url'] ?? null]), pkce: false, tokenAuth: Definition::AUTH_BASIC, authorizationParams: ['owner' => 'user'], profileInTokenResponse: true),
            'dropbox' => new Definition('dropbox', 'Dropbox', 'https://www.dropbox.com/oauth2/authorize', 'https://api.dropboxapi.com/oauth2/token', 'https://api.dropboxapi.com/2/users/get_current_account', ['account_info.read'], static fn(array $data): Profile => new Profile((string) ($data['account_id'] ?? ''), self::text($data['email'] ?? null), (bool) ($data['email_verified'] ?? false), self::text($data['name']['display_name'] ?? null)), authorizationParams: ['token_access_type' => 'offline'], userinfoMethod: 'POST'),
            'reddit' => new Definition('reddit', 'Reddit', 'https://www.reddit.com/api/v1/authorize', 'https://www.reddit.com/api/v1/access_token', 'https://oauth.reddit.com/api/v1/me', ['identity'], static fn(array $data): Profile => new Profile((string) ($data['id'] ?? ''), null, false, self::text($data['name'] ?? null), ['username' => $data['name'] ?? null, 'picture' => $data['icon_img'] ?? null]), pkce: false, tokenAuth: Definition::AUTH_BASIC, authorizationParams: ['duration' => 'permanent'], userinfoHeaders: ['User-Agent' => 'polaris-social/1.0']),
            'kick' => new Definition('kick', 'Kick', 'https://id.kick.com/oauth/authorize', 'https://id.kick.com/oauth/token', 'https://api.kick.com/public/v1/users', ['user:read'], static fn(array $data): Profile => new Profile((string) ($data['data'][0]['user_id'] ?? ''), self::text($data['data'][0]['email'] ?? null), self::text($data['data'][0]['email'] ?? null) !== null, self::text($data['data'][0]['name'] ?? null), ['picture' => $data['data'][0]['profile_picture'] ?? null])),
            'tiktok' => new Definition('tiktok', 'TikTok', 'https://www.tiktok.com/v2/auth/authorize/', 'https://open.tiktokapis.com/v2/oauth/token/', 'https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name,avatar_url', ['user.info.basic'], static fn(array $data): Profile => new Profile((string) ($data['data']['user']['open_id'] ?? ''), null, false, self::text($data['data']['user']['display_name'] ?? null), ['picture' => $data['data']['user']['avatar_url'] ?? null]), clientIdParam: 'client_key', scopeSeparator: ','),
            'huggingface' => new Definition('huggingface', 'Hugging Face', 'https://huggingface.co/oauth/authorize', 'https://huggingface.co/oauth/token', 'https://huggingface.co/oauth/userinfo', ['openid', 'profile', 'email'], static fn(array $data): Profile => self::oidcProfile($data), issuer: 'https://huggingface.co'),
            default => throw new SocialException(SocialException::PROVIDER_NOT_FOUND, sprintf('No provider "%s".', $id)),
        };
    }

    /**
     * The standard OpenID Connect claims: `sub`, `email`, `email_verified`, `name`, `picture`.
     *
     * @param array<string, mixed> $data
     */
    public static function oidcProfile(array $data): Profile
    {
        $subject = $data['sub'] ?? ($data['id'] ?? '');

        return new Profile(
            (string) (is_array($subject) ? (array_key_first($subject) ?? '') : $subject),
            self::text($data['email'] ?? null),
            in_array($data['email_verified'] ?? null, [true, 'true', 1], true),
            self::text($data['name'] ?? null) ?? self::text($data['preferred_username'] ?? null),
            ['picture' => $data['picture'] ?? null],
        );
    }

    private static function text(mixed $value): ?string
    {
        return is_string($value) && str_replace(' ', '', $value) !== '' ? $value : null;
    }
}
