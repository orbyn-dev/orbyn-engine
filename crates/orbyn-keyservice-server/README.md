# orbyn-keyservice-server

The key service's store, on its own Postgres database: migrations, two roles (an
owner, and a runtime role with no `UPDATE`, `DELETE` or `TRUNCATE` on the
append-only tables), the transparency log and the two maps, and head building
without signing. The database is separate from the record server's.
