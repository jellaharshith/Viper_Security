# ADR 0006: Optional Postgres pgvector backend

Status: Implemented with fake-connection tests; live verification pending.

Local embedded Qdrant remains the default. `VIPER_STORE=pgvector` selects the alternative
once CLI wiring is added. `VIPER_DATABASE_URL` is a SecretStr, masked by settings repr,
JSON serialization and `redacted()` (used by health output). Connection failures omit
driver diagnostics, which can contain credentials. Query and transaction failures also omit
driver diagnostics, including failures during commit or rollback. Connection strings belong only in
the ignored `.env` or a secret manager. No database was contacted for this change.

Apply `db/migrations/0001_kb.sql` with an administrative database connection. The application
uses a trusted server-side database role with access to these tables. RLS is enabled on
both tables with no policies; the migration grants nothing to anon/authenticated. Do not
use an anon/PostgREST key for this backend. Live verification of role access is pending.

`PgVectorStore` implements `Store`, with parameterized SQL and validated collection names.
Vectors have 768 finite components. Exact cosine distance (`<=>`) becomes similarity as
`1 - distance`, matching the existing score threshold convention. There is no ANN index:
the initial corpus is small and exact search avoids approximate filtered-search recall
loss. Reconsider above roughly 50,000 records after measuring recall and latency.
Empty collections have no rows, so `exists()` is false until the first nonempty upsert.
Views share a connection; only its creator closes it. Injected connections must use
autocommit so explicit transaction contexts remain the actual commit boundaries.

`PgKBRegistry` lives in pgstore.py and provides active/previous/history, refresh, bootstrap,
promote and rollback without modifying the filesystem registry. Each pointer mutation
locks the singleton row and updates both pointers and history in one transaction.
Concurrent writers read the latest state under the lock. Local snapshots update after
commit (including a no-op bootstrap); long-lived readers must refresh to observe changes
from other processes. A failed initial refresh closes a registry-owned connection.

Integration required in the owning lane: select PgVectorStore using settings.store and
settings.database_url, resolve the active collection from PgKBRegistry, use Store type
annotations in pipeline/update/eval, and route bootstrap/promote/rollback to the selected
registry. The default Qdrant path continues to use KBRegistry. Close database resources
on exit. Apply the migration and verify promote/rollback and RLS on the user's project
before enabling this backend in production. Scheduling and account setup are outside
this change.
