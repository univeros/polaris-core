<?php

declare(strict_types=1);

namespace Polaris\Sso\Saml;

use DateTimeImmutable;
use DOMDocument;
use OneLogin\Saml2\AuthnRequest;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\LogoutRequest;
use OneLogin\Saml2\LogoutResponse;
use OneLogin\Saml2\Metadata;
use OneLogin\Saml2\Response;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;
use Override;
use Polaris\Sso\Identity;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Sp;
use Polaris\Sso\SsoException;
use Throwable;

use function base64_decode;
use function base64_encode;
use function gzdeflate;
use function gzinflate;
use function http_build_query;
use function is_array;
use function is_string;
use function openssl_x509_read;
use function str_contains;
use function strtolower;
use function trim;

/**
 * SAML 2.0 through onelogin/php-saml in strict mode: signed responses or assertions (the IdP
 * certificate), audience, InResponseTo, the conditions with the library's three-minute drift,
 * signature wrapping refused by the library's signed-element validation; the Destination is checked
 * here against the SP URLs (the library would compare with `$_SERVER`). The redirect binding for the
 * AuthnRequest and the logout messages, the POST binding for the Response.
 */
final class OneLoginSamlProtocol implements SamlProtocol
{
    #[Override]
    public function authnRequest(Provider $provider, Sp $sp, string $relayState): array
    {
        $settings = $this->settings($provider, $sp);
        $request = new AuthnRequest($settings);

        return ['id' => $request->getId(), 'url' => self::withQuery((string) $provider->setting('sso_url'), ['SAMLRequest' => $request->getRequest(true), 'RelayState' => $relayState])];
    }

    #[Override]
    public function consume(Provider $provider, Sp $sp, string $samlResponse, ?string $requestId): Identity
    {
        $settings = $this->settings($provider, $sp);
        try {
            $response = new Response($settings, $samlResponse);
            self::assertDestination($response->document, $sp->acsUrl($provider->id));
            if (!$response->isValid($requestId)) {
                throw new SsoException(SsoException::ASSERTION_INVALID, (string) $response->getError());
            }
            $nameId = $response->getNameId();
            $attributes = $response->getAttributes();
            $email = self::first($attributes, $provider->attribute('email')) ?? (str_contains($nameId, '@') ? $nameId : null);
            if ($email === null) {
                throw new SsoException(SsoException::ASSERTION_INVALID, 'the assertion carries no email');
            }
            $notOnOrAfter = $response->getAssertionNotOnOrAfter();
            $notOnOrAfter = $notOnOrAfter > 0 ? $notOnOrAfter : null;

            return new Identity(
                $nameId,
                strtolower(trim($email)),
                self::first($attributes, $provider->attribute('name')),
                $attributes,
                $response->getAssertionId(),
                $notOnOrAfter === null ? null : new DateTimeImmutable('@' . $notOnOrAfter),
                $response->getSessionIndex(),
            );
        } catch (SsoException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new SsoException(SsoException::ASSERTION_INVALID, $exception->getMessage());
        }
    }

    #[Override]
    public function metadata(Provider $provider, Sp $sp): string
    {
        $settings = $this->settings($provider, $sp);
        $metadata = Metadata::builder($settings->getSPData(), false, false, null, null, [], [], [], true);
        if ($sp->certificate !== null) {
            $metadata = Metadata::addX509KeyDescriptors($metadata, $sp->certificate);
        }

        return $metadata;
    }

    #[Override]
    public function logoutUrl(Provider $provider, Sp $sp, string $nameId, ?string $sessionIndex, string $relayState): ?string
    {
        $sloUrl = $provider->setting('slo_url');
        if ($sloUrl === null) {
            return null;
        }
        $request = new LogoutRequest($this->settings($provider, $sp), null, $nameId, $sessionIndex, Constants::NAMEID_EMAIL_ADDRESS);

        return self::withQuery($sloUrl, ['SAMLRequest' => $request->getRequest(true), 'RelayState' => $relayState]);
    }

    #[Override]
    public function consumeLogoutRequest(Provider $provider, Sp $sp, string $samlRequest, bool $deflated): array
    {
        $settings = $this->settings($provider, $sp);
        try {
            $decoded = base64_decode($samlRequest, true);
            $xml = $decoded === false ? '' : ($deflated ? (string) gzinflate($decoded) : $decoded);
            $request = new LogoutRequest($settings, base64_encode($xml));
            $document = new DOMDocument();
            $document->loadXML($xml);
            self::assertDestination($document, $sp->sloUrl($provider->id));
            if (!$request->isValid()) {
                throw new SsoException(SsoException::ASSERTION_INVALID, (string) $request->getError());
            }
            $indexes = [];
            foreach (LogoutRequest::getSessionIndexes($xml) as $index) {
                if (is_string($index)) {
                    $indexes[] = $index;
                }
            }

            return ['id' => LogoutRequest::getID($xml), 'name_id' => LogoutRequest::getNameId($xml, $settings->getSPkey()), 'session_indexes' => $indexes];
        } catch (SsoException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new SsoException(SsoException::ASSERTION_INVALID, $exception->getMessage());
        }
    }

    #[Override]
    public function logoutResponseUrl(Provider $provider, Sp $sp, string $inResponseTo, ?string $relayState): ?string
    {
        $sloUrl = $provider->setting('slo_response_url') ?? $provider->setting('slo_url');
        if ($sloUrl === null) {
            return null;
        }
        $response = new LogoutResponse($this->settings($provider, $sp));
        $response->build($inResponseTo);
        $query = ['SAMLResponse' => $response->getResponse(true)];
        if ($relayState !== null) {
            $query['RelayState'] = $relayState;
        }

        return self::withQuery($sloUrl, $query);
    }

    #[Override]
    public function check(Provider $provider, Sp $sp): array
    {
        $problems = [];
        if ($provider->issuer === '') {
            $problems[] = 'issuer (the IdP entity id) is not set';
        }
        if ($provider->setting('sso_url') === null) {
            $problems[] = 'sso_url is not set';
        }
        $certificate = $provider->setting('certificate');
        if ($certificate === null) {
            $problems[] = 'certificate is not set';
        } elseif (openssl_x509_read(Utils::formatCert($certificate)) === false) {
            $problems[] = 'certificate does not parse as X.509';
        }
        if ($problems === []) {
            try {
                $this->settings($provider, $sp);
            } catch (Throwable $exception) {
                $problems[] = $exception->getMessage();
            }
        }

        return $problems;
    }

    private function settings(Provider $provider, Sp $sp): Settings
    {
        $idp = [
            'entityId' => $provider->issuer,
            'singleSignOnService' => ['url' => (string) $provider->setting('sso_url'), 'binding' => Constants::BINDING_HTTP_REDIRECT],
            'x509cert' => Utils::formatCert((string) $provider->setting('certificate')),
        ];
        if ($provider->setting('slo_url') !== null) {
            $idp['singleLogoutService'] = ['url' => $provider->setting('slo_url'), 'responseUrl' => $provider->setting('slo_response_url') ?? $provider->setting('slo_url'), 'binding' => Constants::BINDING_HTTP_REDIRECT];
        }
        $settings = [
            'strict' => true,
            'debug' => false,
            'baseurl' => $sp->baseUrl,
            'sp' => [
                'entityId' => $sp->entityId($provider->id),
                'assertionConsumerService' => ['url' => $sp->acsUrl($provider->id), 'binding' => Constants::BINDING_HTTP_POST],
                'singleLogoutService' => ['url' => $sp->sloUrl($provider->id), 'binding' => Constants::BINDING_HTTP_REDIRECT],
                'NameIDFormat' => Constants::NAMEID_UNSPECIFIED,
                'x509cert' => $sp->certificate ?? '',
                'privateKey' => $sp->privateKey ?? '',
            ],
            'idp' => $idp,
            'security' => [
                'authnRequestsSigned' => $sp->privateKey !== null,
                'logoutRequestSigned' => $sp->privateKey !== null,
                'logoutResponseSigned' => $sp->privateKey !== null,
                'wantMessagesSigned' => false,
                'wantAssertionsSigned' => false,
                'wantNameId' => true,
                'wantXMLValidation' => true,
                'relaxDestinationValidation' => true,
                'rejectUnsolicitedResponsesWithInResponseTo' => false,
                'signatureAlgorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
                'digestAlgorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256',
            ],
        ];

        return new Settings($settings);
    }

    /**
     * The library compares the Destination with the request's own URL from `$_SERVER`; the SP knows its URL.
     */
    private static function assertDestination(?DOMDocument $document, string $expected): void
    {
        $destination = $document?->documentElement?->getAttribute('Destination') ?? '';
        if ($destination !== '' && $destination !== $expected) {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'the Destination ' . $destination . ' is not this service provider');
        }
    }

    /**
     * @param array<string, mixed> $attributes
     */
    private static function first(array $attributes, string $name): ?string
    {
        $values = $attributes[$name] ?? null;
        $value = is_array($values) ? ($values[0] ?? null) : $values;

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    /**
     * @param array<string, string> $query
     */
    private static function withQuery(string $url, array $query): string
    {
        return $url . (str_contains($url, '?') ? '&' : '?') . http_build_query($query);
    }
}
