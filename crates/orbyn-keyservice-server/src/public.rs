//! What the public API reads: the newest **published** head with its cosignatures, and proofs
//! against it. Every read here is one snapshot (a read-only repeatable-read transaction), so the
//! head and the proofs next to it always belong together, and nothing here can read a stored head
//! that has not been published or an entry past the published head's size.

use orbyn_translog::merkle::inclusion_proof;
use orbyn_translog::{Hash, MapId, Proof};
use sqlx::{PgConnection, Postgres, Row, Transaction};

use crate::head::{self, StoredHead};
use crate::map::MapStore;
use crate::publish::{Nodes, Recorder, load_nodes, needed};
use crate::{Result, Store, StoreError, map_column, to_hash, to_i64, to_u64};

/// Entries in one page of an account's chain.
pub const PAGE: usize = 100;

/// The newest published head and the cosignatures it was published with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedHead {
    pub stored: StoredHead,
    /// `(witness key, Cosignature::encode)` for each witness that cosigned it.
    pub cosignatures: Vec<([u8; 32], [u8; 104])>,
}

/// One entry of an account's chain with its inclusion proof against the head it came with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEntry {
    /// The entry's position in the log.
    pub index: u64,
    /// Its position in its account's chain (the first is 0).
    pub chain_index: u64,
    /// The canonical entry bytes (`Entry::encode`).
    pub entry: Vec<u8>,
    /// RFC 9162 inclusion proof of the entry's leaf in the tree of the head's size.
    pub inclusion_proof: Vec<Hash>,
}

/// A lookup: the map proof for a key at the published head, and its newest entry when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupView {
    pub head: PublishedHead,
    /// The map's root in the head.
    pub root: Hash,
    pub proof: Proof,
    /// The newest entry of the account's chain, when the account has one in the head.
    pub latest: Option<ChainEntry>,
}

/// A page of an account's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPage {
    pub head: PublishedHead,
    pub entries: Vec<ChainEntry>,
    /// The chain index to pass as `after` for the next page, when there is one.
    pub next: Option<u64>,
}

async fn published(conn: &mut PgConnection) -> Result<Option<PublishedHead>> {
    let Some(stored) = head::latest_published(conn).await? else {
        return Ok(None);
    };
    let rows = sqlx::query(
        "SELECT witness_key, cosignature FROM head_cosignatures WHERE head_id = $1 ORDER BY witness_key",
    )
    .bind(stored.id)
    .fetch_all(&mut *conn)
    .await?;
    let cosignatures = rows
        .iter()
        .map(|row| {
            Ok((
                to_hash(row.try_get("witness_key")?, "witness key")?,
                row.try_get::<Vec<u8>, _>("cosignature")?
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("a cosignature"))?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(PublishedHead {
        stored,
        cosignatures,
    }))
}

/// Inclusion proofs for the log positions `indexes` in the tree of the first `size` entries, with
/// the stored subtrees read in one query.
async fn inclusion_proofs(
    conn: &mut PgConnection,
    indexes: &[u64],
    size: u64,
) -> Result<Vec<Vec<Hash>>> {
    let recorder = Recorder(std::cell::RefCell::new(Vec::new()), size);
    let mut wanted = Vec::new();
    for &index in indexes {
        recorder.0.borrow_mut().clear();
        inclusion_proof(&recorder, index, size)
            .map_err(|_| StoreError::Corrupt("an inclusion proof range"))?;
        for (start, end) in recorder.0.borrow().iter() {
            needed(*start, *end, &mut wanted);
        }
    }
    let nodes = Nodes {
        size,
        stored: load_nodes(conn, wanted).await?,
    };
    indexes
        .iter()
        .map(|&index| {
            inclusion_proof(&nodes, index, size)
                .map_err(|_| StoreError::Corrupt("an inclusion proof"))
        })
        .collect()
}

/// The entries of one account's chain with `chain_index > after`, in the published log (position
/// at most `size`), at most `limit` of them.
async fn chain_entries(
    conn: &mut PgConnection,
    map: MapId,
    key: &[u8; 32],
    after: Option<u64>,
    size: u64,
    limit: usize,
    newest_first: bool,
) -> Result<Vec<ChainEntry>> {
    let order = if newest_first { "DESC" } else { "ASC" };
    let sql = format!(
        "SELECT seq, chain_index, payload FROM log_entries \
         WHERE map = $1 AND map_key = $2 AND seq <= $3 AND ($4::bigint IS NULL OR chain_index > $4) \
         ORDER BY chain_index {order} LIMIT $5"
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(map_column(map))
        .bind(key.as_slice())
        .bind(to_i64(size)?)
        .bind(after.map(to_i64).transpose()?)
        .bind(i64::try_from(limit).map_err(|_| StoreError::BadEntry)?)
        .fetch_all(&mut *conn)
        .await?;
    let mut found = Vec::with_capacity(rows.len());
    for row in &rows {
        let seq = to_u64(row.try_get("seq")?)?;
        found.push((
            seq.checked_sub(1)
                .ok_or(StoreError::Corrupt("an entry at position zero"))?,
            to_u64(row.try_get("chain_index")?)?,
            row.try_get::<Vec<u8>, _>("payload")?,
        ));
    }
    let indexes: Vec<u64> = found.iter().map(|(index, _, _)| *index).collect();
    let proofs = inclusion_proofs(conn, &indexes, size).await?;
    Ok(found
        .into_iter()
        .zip(proofs)
        .map(
            |((index, chain_index, entry), inclusion_proof)| ChainEntry {
                index,
                chain_index,
                entry,
                inclusion_proof,
            },
        )
        .collect())
}

impl Store {
    /// A read-only snapshot with the same bounds a write has: a stuck statement is an error.
    async fn snapshot(&self) -> Result<Transaction<'static, Postgres>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)",
        )
        .bind(&self.timeouts.lock)
        .bind(&self.timeouts.statement)
        .execute(&mut *tx)
        .await?;
        Ok(tx)
    }

    /// The newest published head with its cosignatures, or `None` before the first is published.
    pub async fn published_head(&self) -> Result<Option<PublishedHead>> {
        let mut tx = self.snapshot().await?;
        published(&mut tx).await
    }

    /// The consistency proof between two sizes of the **published** log (`0 < from <= to <=` the
    /// published head's size), with that head. `Ok(None)`: nothing is published yet.
    /// `Err(BadHead)`: the sizes are not within the published log.
    pub async fn published_consistency(&self, from: u64, to: u64) -> Result<Option<Vec<Hash>>> {
        let mut tx = self.snapshot().await?;
        let Some(head) = published(&mut tx).await? else {
            return Ok(None);
        };
        if from == 0 || from > to || to > head.stored.head.size {
            return Err(StoreError::BadHead);
        }
        crate::publish::consistency_in(&mut tx, from, to)
            .await
            .map(Some)
    }

    /// A page of an account's chain, proved against the published head. `Ok(None)`: nothing is
    /// published yet. An account with no chain gives an empty page.
    pub async fn published_chain(
        &self,
        map: MapId,
        key: &[u8; 32],
        after: Option<u64>,
        limit: usize,
    ) -> Result<Option<ChainPage>> {
        let mut tx = self.snapshot().await?;
        let Some(head) = published(&mut tx).await? else {
            return Ok(None);
        };
        let size = head.stored.head.size;
        let mut entries = chain_entries(&mut tx, map, key, after, size, limit + 1, false).await?;
        let next = if entries.len() > limit {
            entries.truncate(limit);
            entries.last().map(|e| e.chain_index)
        } else {
            None
        };
        Ok(Some(ChainPage {
            head,
            entries,
            next,
        }))
    }

    /// The lookup of `key` in `map` at the published head. `Ok(None)`: nothing is published yet.
    pub async fn published_lookup(&self, map: MapId, key: &[u8; 32]) -> Result<Option<LookupView>> {
        let mut tx = self.snapshot().await?;
        let Some(head) = published(&mut tx).await? else {
            return Ok(None);
        };
        let root = match map {
            MapId::Service => head.stored.head.service_map_root,
            MapId::Identity => head.stored.head.identity_map_root,
        };
        let proof = MapStore::prove(&mut tx, &root, key).await?;
        let present =
            matches!(proof.end, orbyn_translog::End::Leaf { key: leaf, .. } if leaf == *key);
        let latest = if present {
            chain_entries(&mut tx, map, key, None, head.stored.head.size, 1, true)
                .await?
                .into_iter()
                .next()
        } else {
            None
        };
        Ok(Some(LookupView {
            head,
            root,
            proof,
            latest,
        }))
    }
}
