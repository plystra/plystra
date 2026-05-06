# Ent Database Management

Plystra now uses Ent as the canonical Go schema model for Core database objects.

The SQL files in `migrations/` remain the ordered, checksum-verified migration history. Ent is used for:

- type-safe schema definitions in `ent/schema`
- generated entity builders and query APIs in `ent`
- non-destructive schema apply checks through `plystractl ent apply`
- schema presence checks through `plystractl ent status`

This split keeps production upgrades auditable while allowing Core code to migrate from raw SQL toward Ent incrementally.

## Commands

Regenerate Ent code after editing `ent/schema`:

```powershell
go run entgo.io/ent/cmd/ent generate ./ent/schema
```

Check that Ent-managed tables are present:

```powershell
go run .\cmd\plystractl ent status
```

Apply the Ent schema without dropping existing columns or indexes:

```powershell
go run .\cmd\plystractl ent apply
```

## Modeling Notes

- All first-class tables use Plystra's existing text IDs.
- `role_permissions` is modeled as a first-class Ent schema with its own `id`, preserving the v1.0 requirement that important relationship tables stay explicit.
- JSON/JSONB columns are modeled as Ent JSON fields.
- Existing raw SQL store methods remain in place while repository access is migrated module by module.
