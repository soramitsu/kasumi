//! A synchronous, single-owner Node-API binding for the live Kasumi engine.
#![cfg(unix)]

use kasumi_frozen_run::{
    LiveDb, MAX_KEY, MAX_VALUE, MAX_WAL_BATCH_BYTES, MAX_WAL_BATCH_OPS, WalOp,
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
    pub fn create(path: String) -> Result<Self> {
        Ok(Self {
            db: RefCell::new(Some(
                LiveDb::create(path).map_err(|e| storage("create", e))?,
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
        let count = operations.len() as usize;
        if count > MAX_WAL_BATCH_OPS {
            return Err(invalid("too many operations in a Kasumi batch"));
        }
        let mut owned = Vec::with_capacity(count);
        let mut bytes = 0;
        for i in 0..operations.len() {
            let item: Object<'_> = operations
                .get(i)?
                .ok_or_else(|| invalid("missing Kasumi batch operation"))?;
            let key: BufferSlice<'_> = item.get_named_property("key")?;
            key_within_limit(&key)?;
            bytes += key.len();
            if bytes > MAX_WAL_BATCH_BYTES {
                return Err(invalid("Kasumi batch exceeds the byte limit"));
            }
            // A later JS property getter may detach or mutate earlier inputs.
            // Snapshot each slice before reading another user-controlled property.
            let key = key.to_vec();
            let value = if item.has_named_property("value")? {
                let value: BufferSlice<'_> = item.get_named_property("value")?;
                if value.len() > MAX_VALUE || value.len() > MAX_WAL_BATCH_BYTES - bytes {
                    return Err(invalid("Kasumi value or batch exceeds the byte limit"));
                }
                bytes += value.len();
                Some(value.to_vec())
            } else {
                None
            };
            owned.push((key, value));
        }
        let ops: Vec<_> = owned
            .iter()
            .map(|(key, value)| match value {
                Some(value) => WalOp::Put(key, value),
                None => WalOp::Delete(key),
            })
            .collect();
        self.inner()?
            .commit(&ops)
            .map(BigInt::from)
            .map_err(|e| storage("commit", e))
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
