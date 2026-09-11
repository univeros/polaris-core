<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Organization;

use Polaris\Sso\Model\Provider;

use function filter_var;
use function in_array;
use function is_array;
use function is_bool;
use function is_string;
use function mb_strlen;
use function preg_match;
use function trim;

use const FILTER_VALIDATE_URL;

/**
 * The validated fields of a provider from a request body: what `Providers::create()` and `update()` take,
 * or the errors.
 */
final readonly class ProviderInput
{
    private const array SAML_KEYS = ['sso_url', 'slo_url', 'slo_response_url', 'certificate', 'idp_initiated'];
    private const array OIDC_KEYS = ['issuer', 'client_id', 'client_secret', 'scopes'];

    /**
     * @param array<string, mixed> $config
     * @param array<string, string> $attributes
     * @param array{enabled: bool, roles: list<string>} $jit
     * @param list<string> $redirectUris
     */
    private function __construct(
        public string $type,
        public string $name,
        public string $issuer,
        public array $config,
        public array $attributes,
        public array $jit,
        public array $redirectUris,
        public bool $enabled,
    ) {
    }

    /**
     * @param array<string, mixed> $body
     * @return self|list<string> the input, or the errors
     */
    public static function from(array $body, ?Provider $existing = null): self|array
    {
        $errors = [];
        $type = $existing !== null ? $existing->type : ($body['type'] ?? null);
        if (!in_array($type, [Provider::SAML, Provider::OIDC], true)) {
            return ['type must be saml or oidc.'];
        }
        $name = is_string($body['name'] ?? null) ? trim($body['name']) : ($existing !== null ? $existing->name : '');
        if ($name === '' || mb_strlen($name) > 120) {
            $errors[] = 'name must be 1 to 120 characters.';
        }
        $issuer = is_string($body['issuer'] ?? null) ? trim($body['issuer']) : ($existing !== null ? $existing->issuer : '');
        if ($issuer === '' || mb_strlen($issuer) > 512) {
            $errors[] = 'issuer is required (the IdP entity id, or the OIDC issuer URL).';
        }
        $config = is_array($body['config'] ?? null) ? $body['config'] : ($existing !== null && !isset($body['config']) ? $existing->config() : []);
        $config = self::config($type, $config, $errors);
        $attributes = [];
        foreach (is_array($body['attributes'] ?? null) ? $body['attributes'] : ($existing !== null && !isset($body['attributes']) ? self::decode($existing->attributes) : []) as $field => $claim) {
            if (!is_string($field) || !is_string($claim) || $claim === '') {
                $errors[] = 'attributes must map field names to claim or attribute names.';
                break;
            }
            $attributes[$field] = $claim;
        }
        $jit = is_array($body['jit'] ?? null) ? $body['jit'] : ($existing !== null && !isset($body['jit']) ? ['enabled' => $existing->jitEnabled(), 'roles' => $existing->jitRoles()] : []);
        $roles = [];
        foreach (is_array($jit['roles'] ?? null) ? $jit['roles'] : [] as $slug) {
            if (!is_string($slug) || preg_match('/^[a-z0-9][a-z0-9_-]{0,63}$/', $slug) !== 1) {
                $errors[] = 'jit.roles must be a list of role slugs.';
                break;
            }
            $roles[] = $slug;
        }
        $redirectUris = [];
        $redirectUrisValid = true;
        foreach (is_array($body['redirect_uris'] ?? null) ? $body['redirect_uris'] : ($existing !== null && !isset($body['redirect_uris']) ? $existing->redirectUris() : []) as $uri) {
            if (!is_string($uri) || filter_var($uri, FILTER_VALIDATE_URL) === false || preg_match('#^https?://#', $uri) !== 1) {
                $errors[] = 'redirect_uris must be a list of http(s) URLs.';
                $redirectUrisValid = false;
                break;
            }
            $redirectUris[] = $uri;
        }
        if ($redirectUris === [] && $redirectUrisValid) {
            $errors[] = 'redirect_uris needs at least one URL the sign-in may end on.';
        }
        $enabled = $body['enabled'] ?? ($existing !== null ? $existing->enabled : true);
        if (!is_bool($enabled)) {
            $errors[] = 'enabled must be a boolean.';
        }
        if ($errors !== []) {
            return $errors;
        }

        return new self($type, $name, $issuer, $config, $attributes, ['enabled' => ($jit['enabled'] ?? false) === true, 'roles' => $roles], $redirectUris, (bool) $enabled);
    }

    /**
     * @param array<string, mixed> $config
     * @param list<string> $errors
     * @return array<string, mixed>
     */
    private static function config(string $type, array $config, array &$errors): array
    {
        $clean = [];
        foreach ($type === Provider::SAML ? self::SAML_KEYS : self::OIDC_KEYS as $key) {
            if (isset($config[$key]) && $config[$key] !== '') {
                $clean[$key] = $config[$key];
            }
        }
        if ($type === Provider::SAML) {
            foreach (['sso_url', 'slo_url', 'slo_response_url'] as $url) {
                if (isset($clean[$url]) && (!is_string($clean[$url]) || filter_var($clean[$url], FILTER_VALIDATE_URL) === false)) {
                    $errors[] = 'config.' . $url . ' must be a URL.';
                }
            }
            if (!isset($clean['sso_url'])) {
                $errors[] = 'config.sso_url is required.';
            }
            if (!is_string($clean['certificate'] ?? null)) {
                $errors[] = 'config.certificate (the IdP signing certificate, PEM or base64) is required.';
            }
            if (isset($clean['idp_initiated']) && !is_bool($clean['idp_initiated'])) {
                $errors[] = 'config.idp_initiated must be a boolean.';
            }
        } else {
            if (!is_string($clean['client_id'] ?? null)) {
                $errors[] = 'config.client_id is required.';
            }
            foreach (['client_secret', 'scopes', 'issuer'] as $text) {
                if (isset($clean[$text]) && !is_string($clean[$text])) {
                    $errors[] = 'config.' . $text . ' must be a string.';
                }
            }
        }

        return $clean;
    }

    /**
     * @return array<string, mixed>
     */
    private static function decode(string $json): array
    {
        $decoded = json_decode($json, true);

        return is_array($decoded) ? $decoded : [];
    }
}
