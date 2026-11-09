use super::model::{PageRow, record};
use crate::zones::find;
use crate::{ChangeToken, Changes, Result, Store, StoreError, check_zone_name, require_trusted};
use orbyn_core::accounts::Session;

impl Store {
    /// The changes after `since` (the start of the zone when `None`), oldest
    /// first, with the latest state of each record. A token from another zone
    /// or past the zone's sequence is refused.
    pub async fn fetch_changes(
        &self,
        session: &Session,
        zone: &str,
        since: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Changes> {
        check_zone_name(zone)?;
        let limit = match limit {
            None => self.limits.max_fetch,
            Some(n) if (1..=self.limits.max_fetch).contains(&n) => n,
            Some(_) => return Err(StoreError::BatchTooLarge),
        };
        require_trusted(&self.pool, session, false).await?;
        // One snapshot for the zone row and its records. The floor check
        // below is only sound if the purge is either wholly visible (the floor
        // is raised and the tombstones are gone) or wholly invisible (neither),
        // and two statements under READ COMMITTED could see one and not the
        // other. The zone's sequence read first is also safe: every write up
        // to it has committed, because writes hold the zone row until they do.
        let mut tx = self
            .pool
            .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .await?;
        let row = find(&mut *tx, session, zone, false).await?;
        let mut resuming = false;
        let from = match since {
            None => 0,
            Some(text) => {
                let token = ChangeToken::parse(text).ok_or(StoreError::InvalidToken)?;
                if !token.fits(row.id, row.seq) {
                    return Err(StoreError::InvalidToken);
                }
                // The device may have missed a delete that was purged since.
                // A token from the middle of a fetch from the start is exempt
                // while the floor is the one it was made under: that device
                // reads what the purge left, whatever it held before.
                let expired = match token.floor() {
                    None => token.seq() < row.purge_floor,
                    Some(made_under) => made_under != row.purge_floor,
                };
                if expired {
                    return Err(StoreError::TokenExpired);
                }
                resuming = token.floor().is_some();
                token.seq()
            }
        };
        #[cfg(test)]
        if let Some(gap) = &self.gap {
            (gap.0)().await;
        }
        let fetch = i64::try_from(limit + 1).map_err(|_| StoreError::Internal)?;
        let rows: Vec<PageRow> =
            sqlx::query_as(
                "SELECT record_id, record_type, version, ciphertext, wrapped_key, author_device_id,
                        modified_at, deleted, delete_proof,
                        (sum(coalesce(octet_length(ciphertext), 0) + coalesce(octet_length(wrapped_key), 0))
                            OVER (ORDER BY version))::bigint AS running
                 FROM records WHERE zone_id = $1 AND version > $2 AND version <= $3
                 ORDER BY version LIMIT $4",
            )
            .bind(row.id)
            .bind(from)
            .bind(row.seq)
            .bind(fetch)
            .fetch_all(&mut *tx)
            .await?;
        let mut records = Vec::new();
        let mut more = false;
        for (i, row) in rows.into_iter().enumerate() {
            if i >= limit || (i > 0 && row.running > self.limits.fetch_bytes) {
                more = true;
                break;
            }
            records.push(record(row.record));
        }
        let seq = match (more, records.last()) {
            (true, Some(last)) => last.version,
            _ => row.seq,
        };
        // Reading from the start (or resuming that) below the purge floor: the
        // next token must not look like a stale one.
        let from_start = since.is_none() || resuming;
        let token = if more && from_start && seq < row.purge_floor {
            ChangeToken::partial(row.id, seq, row.purge_floor)
        } else {
            ChangeToken::new(row.id, seq)
        };
        Ok(Changes {
            records,
            token,
            more,
            zone_deleted: row.deleted,
        })
    }
}
