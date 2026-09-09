# Decisions log

Append one entry per decision. Format: date, work package, decision, reason, alternatives rejected.

## Open at start (decide in the WP indicated)

- **WP2** — `criteria` semantics for `RepositoryInterface::findBy/findOneBy`: equality, IN for lists, IS NULL for null. Confirm the domain uses nothing else; if it does, list it here.
- **WP2** — Default `EncrypterInterface`: libsodium XChaCha20-Poly1305 keyed from `Secrets`. Confirm key derivation is compatible with data encrypted by 1.0 (TOTP secrets), or provide a re-encryption path in `UPGRADE.md`.
- **WP3** — Identity map scope for `GenericRepository::persist` (per request vs per transaction).
- **WP4** — Reimplementation of the single `Cycle\Database\Injection\Fragment` usage per dialect.
- **WP5** — Meaning of the `suspended` validation rule (one occurrence) and whether it is validation or authorization.
- **WP5** — Whether `users/disable` stays `destructive` (see `effects.md`).
- **WP6** — Fixture normalisation rules (ids, timestamps, tokens, OTP codes) for the contract freeze.
- **WP1** — Which tests depend on Univeros wiring and are skipped until WP4/WP7 (keep the list here and empty it).
- **Any** — PHP minimum stays 8.3 (do not raise during extraction).

## Log

<!-- YYYY-MM-DD · WPn · decision · reason · rejected alternatives -->
