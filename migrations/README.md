# Database Migrations

This directory contains SQL migration files applied by `update.sh` in
alphabetical order. Each is recorded in the `schema_migrations` table by
filename and applied only once.

## Baseline

`000_baseline.sql` is a **consolidated squash** of the historical migrations
(the old `000`–`085`), generated from the production schema. It is idempotent
(`CREATE TABLE IF NOT EXISTS` + `INSERT IGNORE`): it builds the complete schema
and seeds reference data (protocols with their install scripts, protocol
variables/templates, translations, languages, roles) on a fresh database, and
is a no-op on an existing one. Runtime and secret data (servers, clients,
metrics, users, api keys, alerts) is **not** seeded.

An install whose schema predates migration tracking has no `schema_migrations`
rows; `update.sh` detects the existing schema and records `000_baseline.sql` as
already applied instead of re-running it.

New migrations continue from `086_...` onward.

## Adding New Migrations

1. Use a numerical prefix higher than the baseline (e.g. `086_add_feature.sql`).
2. Use descriptive names.
3. Make them idempotent — `CREATE TABLE IF NOT EXISTS`, `ALTER` guarded by an
   `information_schema` check, `INSERT ... ON DUPLICATE KEY UPDATE` / `INSERT IGNORE`.

## Regenerating the baseline

If the schema drifts far enough to warrant a new squash, regenerate from the
authoritative DB (structure for all tables made `IF NOT EXISTS`, plus
`--insert-ignore` data for the reference tables only) and re-validate that it
reproduces the live schema on a throwaway database before replacing.

## Manual Execution

To manually run migrations in an existing database:

```bash
# The baseline (or any single migration)
docker compose exec -T db mysql -uroot -prootpassword amnezia_panel < migrations/000_baseline.sql

# All migrations in order
for file in migrations/*.sql; do
  echo "Executing $file..."
  docker compose exec -T db mysql -uroot -prootpassword amnezia_panel < "$file"
done
```

## Regenerating Translation Migrations

To regenerate translation migrations from the current database:

```bash
# Export translations for a specific language
docker compose exec -T db mysql -uroot -prootpassword amnezia_panel \
  --default-character-set=utf8mb4 \
  -e "SELECT CONCAT('(''', language_code, ''', ''', translation_key, ''', ''', 
      REPLACE(translation_value, '''', ''''''), '''),') 
      FROM translations WHERE language_code = 'ru' ORDER BY translation_key;" \
  | grep -v "CONCAT" > /tmp/translations_ru.sql

# Then wrap with INSERT statement and ON DUPLICATE KEY UPDATE
```
