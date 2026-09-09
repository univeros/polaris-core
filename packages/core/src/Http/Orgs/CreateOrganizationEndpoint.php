<?php

declare(strict_types=1);

namespace Polaris\Http\Orgs;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use InvalidArgumentException;
use Override;
use Polaris\Authorization\OrganizationService;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Exception\OrganizationSlugConflictException;

use function is_string;
use function mb_strlen;
use function preg_match;
use function trim;

/**
 * `POST /orgs` — create an organization; the verified caller becomes its owner.
 *
 * Requires an authenticated, email-verified user (read from the access token). The
 * {@see OrganizationService} performs the transactional create (org + cloned role templates +
 * active owner membership). Slug is optional and auto-derived from the name when omitted.
 */
final class CreateOrganizationEndpoint extends Endpoint
{
    public function __construct(private readonly OrganizationService $organizations)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $userId = (string) $token->getMetadata('sub');
        if ($userId === '') {
            return $this->unauthorized();
        }

        if ($token->getMetadata('email_verified') !== true) {
            return $this->respond(403, [
                'error' => 'email_unverified',
                'message' => 'Verify your email address before creating an organization.',
            ]);
        }

        $errors = [];

        $nameInput = $input->get('name');
        $name = is_string($nameInput) ? trim($nameInput) : '';
        if ($name === '') {
            $errors[] = 'A name is required.';
        } elseif (mb_strlen($name) > 160) {
            $errors[] = 'The name must be at most 160 characters.';
        }

        $slug = null;
        $slugInput = $input->get('slug');
        if ($slugInput !== null && $slugInput !== '') {
            if (is_string($slugInput) && preg_match('/^[a-z0-9-]+$/', $slugInput) === 1 && mb_strlen($slugInput) <= 160) {
                $slug = $slugInput;
            } else {
                $errors[] = 'The slug must be URL-safe (lowercase letters, digits and hyphens) and at most 160 characters.';
            }
        }

        if ($errors !== []) {
            return $this->unprocessable($errors);
        }

        try {
            $organization = $this->organizations->create($name, $slug, $userId);
        } catch (OrganizationSlugConflictException) {
            return $this->respond(409, ['error' => 'conflict', 'message' => 'That slug is already taken.']);
        } catch (InvalidArgumentException $exception) {
            return $this->unprocessable([$exception->getMessage()]);
        }

        return $this->respond(201, [
            'data' => [
                'id' => $organization->id,
                'name' => $organization->name,
                'slug' => $organization->slug,
                'role' => PermissionCatalog::ROLE_OWNER,
            ],
        ]);
    }
}
