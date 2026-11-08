//! A synchronous, single-owner Node-API binding for the live Kasumi engine.
#![cfg(unix)]

use kasumi_frozen_run::{
    LIVE_GROUP_MAX_BATCHES, LIVE_GROUP_MAX_BYTES, LiveDb, MAX_KEY, MAX_VALUE, MAX_WAL_BATCH_BYTES,
    MAX_WAL_BATCH_OPS, WalOp,
};
use napi::bindgen_prelude::{Array, BigInt, Buffer, BufferSlice, JsObjectValue, Object};
use napi::{Error, Result, Status};
use napi_derive::napi;
use std::cell::{RefCell, RefMut};
use std::io;
use std::ops::Bound;

const MAX_RANGE_ROWS: usize = 4096;
const MAX_RANGE_BYTES: usize = 64 << 20;

fn invalid(message: impl Into<String>) -> Error {
    Error::new(Status::InvalidArg, message.into())
}

fn storage(context: &str, error: io::Error) -> Error {
    Error::from_reason(format!("Kasumi {context}: {error}"))
}

fn key_within_limit(key: &[u8]) -> Result<()> {
    if key.len() > MAX_KEY {
        return Err(invalid("key exceeds the Kasumi byte limit"));
    }
    Ok(())
}

#[napi(object, object_from_js = false)]
pub struct RangeRow {
    pub key: Buffer,
    pub value: Buffer,
}

fn bound_from(key: Option<&[u8]>, inclusive: bool) -> Bound<&[u8]> {
    match key {
        Some(key) if inclusive => Bound::Included(key),
        Some(key) => Bound::Excluded(key),
        None => Bound::Unbounded,
    }
}

fn optional_key(options: &Object<'_>, field: &str) -> Result<Option<Vec<u8>>> {
    let Some(key) = options.get_named_property::<Option<BufferSlice<'_>>>(field)? else {
        return Ok(None);
    };
    key_within_limit(&key)?;
    Ok(Some(key.to_vec()))
}

struct BatchInputs(Vec<(Vec<u8>, Option<Vec<u8>>)>);

impl BatchInputs {
    fn decode(operations: Array<'_>, ops_left: &mut usize, bytes_left: &mut usize) -> Result<Self> {
        let count = operations.len() as usize;
        if count > *ops_left {
            return Err(invalid("too many operations in a Kasumi batch"));
        }
        *ops_left -= count;
        let mut owned = Vec::with_capacity(count);
        for i in 0..operations.len() {
            let item: Object<'_> = operations
                .get(i)?
                .ok_or_else(|| invalid("missing Kasumi batch operation"))?;
            let key: BufferSlice<'_> = item.get_named_property("key")?;
            key_within_limit(&key)?;
            if key.len() > *bytes_left {
                return Err(invalid("Kasumi batch exceeds the byte limit"));
            }
            *bytes_left -= key.len();
            // A later JS property getter may detach or mutate earlier inputs.
            // Snapshot each slice before reading another user-controlled property.
            let key = key.to_vec();
            let value = if item.has_named_property("value")? {
                let value: BufferSlice<'_> = item.get_named_property("value")?;
                if value.len() > MAX_VALUE || value.len() > *bytes_left {
                    return Err(invalid("Kasumi value or batch exceeds the byte limit"));
                }
                *bytes_left -= value.len();
                Some(value.to_vec())
            } else {
                None
            };
            owned.push((key, value));
        }
        Ok(Self(owned))
    }

    fn ops(&self) -> Vec<WalOp<'_>> {
        self.0
            .iter()
            .map(|(key, value)| match value {
                Some(value) => WalOp::Put(key, value),
                None => WalOp::Delete(key),
            })
            .collect()
    }
}

/// Synchronous operations can be run on the indexer's dedicated worker thread.
#[napi]
pub struct LiveDatabase {
    db: RefCell<Option<LiveDb>>,
}

impl LiveDatabase {
    fn inner(&self) -> Result<RefMut<'_, LiveDb>> {
        let handle = self
            .db
            .try_borrow_mut()
            .map_err(|_| Error::from_reason("Kasumi database is busy"))?;
        RefMut::filter_map(handle, |slot| slot.as_mut())
            .map_err(|_| Error::from_reason("Kasumi database is closed"))
    }
}

#[napi]
impl LiveDatabase {
    #[napi(factory)]
    pub fn create(path: String, write_buffer_bytes: Option<f64>) -> Result<Self> {
        let budget =
            write_buffer_bytes.unwrap_or(kasumi_frozen_run::LIVE_DEFAULT_BUFFER_BYTES as f64);
        if !budget.is_finite() || budget.fract() != 0.0 || budget < 0.0 {
            return Err(invalid("write buffer must be an integer byte count"));
        }
        Ok(Self {
            db: RefCell::new(Some(
                LiveDb::create_with_buffer(path, budget as u64)
                    .map_err(|e| storage("create", e))?,
            )),
        })
    }

    #[napi(factory)]
    pub fn open(path: String) -> Result<Self> {
        Ok(Self {
            db: RefCell::new(Some(LiveDb::open(path).map_err(|e| storage("open", e))?)),
        })
    }

    /// Return the full 64-bit sequence without converting through a JavaScript number.
    #[napi]
    pub fn sequence(&self) -> Result<BigInt> {
        Ok(self.inner()?.sequence().into())
    }

    /// Submit one ordered batch. A present Buffer value is a put; omission is a delete.
    #[napi]
    pub fn commit(&self, operations: Array<'_>) -> Result<BigInt> {
        let mut ops_left = MAX_WAL_BATCH_OPS;
        let mut bytes_left = MAX_WAL_BATCH_BYTES;
        let owned = BatchInputs::decode(operations, &mut ops_left, &mut bytes_left)?;
        self.inner()?
            .commit(&owned.ops())
            .map(BigInt::from)
            .map_err(|e| storage("commit", e))
    }

    /// Group already available independent batches behind one WAL synchronization.
    #[napi]
    pub fn commit_group(&self, batches: Array<'_>) -> Result<Vec<BigInt>> {
        let count = batches.len() as usize;
        if count > LIVE_GROUP_MAX_BATCHES {
            return Err(invalid("too many batches in live group"));
        }
        let mut ops_left = MAX_WAL_BATCH_OPS;
        let mut bytes_left = if count > 1 {
            LIVE_GROUP_MAX_BYTES as usize
        } else {
            MAX_WAL_BATCH_BYTES
        };
        let mut owned = Vec::with_capacity(count);
        for i in 0..batches.len() {
            let batch = batches
                .get(i)?
                .ok_or_else(|| invalid("missing Kasumi group batch"))?;
            owned.push(BatchInputs::decode(batch, &mut ops_left, &mut bytes_left)?);
        }
        let ops: Vec<_> = owned.iter().map(BatchInputs::ops).collect();
        let slices: Vec<_> = ops.iter().map(Vec::as_slice).collect();
        self.inner()?
            .commit_group(&slices)
            .map(|sequences| sequences.into_iter().map(BigInt::from).collect())
            .map_err(|e| storage("commitGroup", e))
    }

    #[napi]
    pub fn get(&self, key: BufferSlice<'_>) -> Result<Option<Buffer>> {
        key_within_limit(&key)?;
        self.inner()?
            .get(&key)
            .map(|v| v.map(Buffer::from))
            .map_err(|e| storage("get", e))
    }

    /// Bounds always describe ascending key space, including during reverse scans.
    #[napi]
    pub fn range(&self, options: Object<'_>) -> Result<Vec<RangeRow>> {
        let limit: f64 = options.get_named_property("limit")?;
        if !limit.is_finite()
            || limit.trunc() != limit
            || !(0.0..=MAX_RANGE_ROWS as f64).contains(&limit)
        {
            return Err(invalid(format!(
                "limit must be an integer between 0 and {MAX_RANGE_ROWS}"
            )));
        }
        let start = optional_key(&options, "start")?;
        let end = optional_key(&options, "end")?;
        let start_exclusive: Option<bool> = options.get_named_property("startExclusive")?;
        let end_inclusive: Option<bool> = options.get_named_property("endInclusive")?;
        let reverse: Option<bool> = options.get_named_property("reverse")?;
        let lower = bound_from(start.as_deref(), !start_exclusive.unwrap_or(false));
        let upper = bound_from(end.as_deref(), end_inclusive.unwrap_or(false));
        let mut db = self.inner()?;
        let mut rows = Vec::new();
        let mut bytes = 0;
        let emit = |key: &[u8], value: &[u8]| -> io::Result<()> {
            bytes += key.len() + value.len();
            if bytes > MAX_RANGE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "range exceeds 64 MiB; reduce limit or narrow key bounds",
                ));
            }
            rows.push(RangeRow {
                key: key.to_vec().into(),
                value: value.to_vec().into(),
            });
            Ok(())
        };
        if reverse.unwrap_or(false) {
            db.visit_reverse(lower, upper, limit as usize, emit)
        } else {
            db.visit_forward(lower, upper, limit as usize, emit)
        }
        .map_err(|e| storage("range", e))?;
        Ok(rows)
    }

    #[napi]
    pub fn checkpoint(&self) -> Result<()> {
        self.inner()?
            .checkpoint()
            .map_err(|e| storage("checkpoint", e))
    }

    /// Drop the exclusive directory lock. Repeated closes are harmless.
    #[napi]
    pub fn close(&self) -> Result<()> {
        self.db
            .try_borrow_mut()
            .map_err(|_| Error::from_reason("Kasumi database is busy"))?
            .take();
        Ok(())
    }
}
