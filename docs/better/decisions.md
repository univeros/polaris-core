# Decisions log (program 4, "Better Auth for PHP")

Append one entry per decision. Format: date, work package, decision, reason, alternatives rejected.
Program 1's log is `../extraction/decisions.md`, program 2's `../adapters/decisions.md`, program 3's
`../plugins/decisions.md`. The defaults the spec applies before any WP opened are its §9; they become
entries here when a WP confirms or changes them.

## Log

- 2026-10-09 · spec · Program 4 is ten plugins, two agent SDKs and the developer surface in this
  repository; no new repository; core's 52 routes stay frozen; identifiers are side tables (program 3,
  WP0); ids are UUID v7. · Rejected: a `polaris/better` meta-package (nothing to put in it that
  `polaris init --plugins` does not do); a separate `polaris-agents` repository (it is a plugin like the
  six before it).
