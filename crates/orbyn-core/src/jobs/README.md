# Jobs

The Postgres job queue. Workers claim jobs with `FOR UPDATE SKIP LOCKED`, so many
workers share one queue without taking the same job twice. A job carries its
attempts, its payload and the caller's operation identity, so a redelivered job
never repeats an effect. Finished and failed rows are pruned by the worker.

| Module | Owns |
| --- | --- |
| `mod.rs` | Job records, enqueue, claim, completion, retry and prune |
