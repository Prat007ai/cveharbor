# Forward migrations after the verified production baseline

New application migrations use unique, monotonically increasing filenames here
(e.g. `0001_add_example.sql`) and Cloudflare D1's `d1_migrations` ledger. Never
rename or edit an applied migration. Historical application SQL stays in its
existing manifest; do not copy it into this directory or replay it in production.

The same files run in staging first and production only after approval of the
exact tested commit. Destructive statements require a separately approved
maintenance operation; routine automation stops rather than accepting a flag.
No migration is run until the live production baseline has been verified.
