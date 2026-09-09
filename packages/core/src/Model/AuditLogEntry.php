<?php

declare(strict_types=1);

namespace Polaris\Model;

use DateTimeImmutable;

/**
 * One append-only security audit record (table `auth_audit_log`).
 *
 * Rows mirror the PSR-14 domain events (`docs/auth/events.md`): the event name, the acting user
 * and org context where known, the client network context, and a JSON {@see $metadata} blob of
 * event-specific identifiers — **never secrets** (tokens, codes, hashes are excluded by the
 * whitelist in {@see \Univeros\Polaris\Observability\AuditLogListener}). Rows are written once and
 * never updated or deleted by the module; retention/archival is host policy
 * (`docs/auth/data-model.md` §3).
 */
class AuditLogEntry
{
    public string $id = '';

    /** The acting user; null for anonymous attempts. */
    public ?string $actorUserId = null;
    public ?string $organizationId = null;

    /** The PSR-14 event name, e.g. `user.logged_in`. */
    public string $event = '';
    public ?string $ip = null;
    public ?string $userAgent = null;

    /** JSON-encoded event-specific identifiers; never secrets. */
    public string $metadata = '{}';
    public DateTimeImmutable $createdAt;
}
