# Applied Supabase migration ledger — historical evidence

These SQL files are **verbatim statements already applied** in the canonical OrdaX Platform database, recovered from the read-only Supabase migration ledger on 2026-10-30. Their on-disk version is the actual database ledger version, not a new deployment instruction.

**Never apply/replay these files**. They are immutable audit/provenance snapshots for migrations that were executed before their source was present in this repository. New migrations must be created under `control-plane/supabase/migrations/` through the normal branch, PR, migration registry and verification flow. The canonical registry remains `control-plane/supabase/migration-registry.json`; no second authority is created by this archive.

Do not edit these historical statements to reflect later schema changes; use a new migration for future changes.
