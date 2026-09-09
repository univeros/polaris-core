# Behaviour changes introduced by extraction

The goal is for this file to stay empty. If removing a framework dependency forces an observable change (response body, status, header, timing, token format, event payload), record it here before merging, with the reason and the affected spec file(s). Anything listed here must also appear in `UPGRADE.md`.

| Date | WP | Change | Reason | Affected specs |
|---|---|---|---|---|
| 2026-09-09 | WP6 | A request body field named like a request attribute (the 1.0 test posted `polaris:mfa:ticket` to `/auth/mfa/verify`) no longer overrides the attribute. 1.0 merged the body over the attributes, so the string clobbered the typed MFA ticket and the endpoint answered 401 `unauthorized`; `Polaris\Http\Input` keeps attributes apart from request data, so the spoofed field is ignored and the request proceeds for the ticket's own principal (here 422 `invalid_code`, the wrong recovery code). No principal can be spoofed either way; the new shape is the safer one and is what the contract-freeze suite pins from now on (`tests/Contract/KnownChanges`). | Removing the framework `InputCollection` merge (spec §5.1). | `auth/mfa/verify.yaml` (and any endpoint receiving such a body field) |
