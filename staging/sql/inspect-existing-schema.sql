-- Read-only structural inventory. Run only in the verified permanent staging D1.
-- No customer rows, migration changes, reset, or restore operations.
SELECT type, name, tbl_name, sql
FROM sqlite_schema
WHERE type IN ('table', 'index', 'trigger', 'view')
  AND name NOT GLOB 'sqlite_*'
ORDER BY type, name;
