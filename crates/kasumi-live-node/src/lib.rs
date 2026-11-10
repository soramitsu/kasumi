//! A synchronous, single-owner Node-API binding for the live Kasumi engine.
#![cfg(unix)]

use kasumi_frozen_run::{
    LIVE_GROUP_MAX_BATCHES, LIVE_GROUP_MAX_BYTES, LiveDb, MAX_KEY, MAX_VALUE, MAX_WAL_BATCH_BYTES,
    MAX_WAL_BATCH_OPS, WalOp,
};
use napi::bindgen_prelude::{
    Array, BigInt, Buffer, BufferSlice, FromNapiValue, JsObjectValue, Object,
};
use napi::{Env, Error, JsValue, Result, Status, Unknown};
use napi_derive::napi;
use std::cell::{RefCell, RefMut};
use std::io;
use std::ops::Bound;

const SMALL_READ_BYTES: usize = 4096;
const MAX_RANGE_ROWS: usize = 4096;
mod packed;
use packed::MAX_RANGE_BYTES;

fn invalid(message: impl Into<String>) -> Error {
    Error::new(Status::InvalidArg, message.into())
}

fn storage(context: &str, error: io::Error) -> Error {
    Error::from_reason(format!("Kasumi {context}: {error}"))
}

// SharedArrayBuffer can be mutated by another JS worker during a synchronous call.
// Read the actual typed-array backing store, not the overridable JS "buffer" property.
fn validate_private_buffer(value: Unknown<'_>) -> Result<()> {
    if !value.is_buffer()? {
        return Err(invalid("Kasumi expects a Buffer"));
    }
    let raw = value.value();
    let mut backing = std::ptr::null_mut();
    let mut private = false;
    // All handles belong to this call's environment and both output pointers live until return.
    napi::check_status!(unsafe {
        napi::sys::napi_get_typedarray_info(
            raw.env,
            raw.value,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut backing,
            std::ptr::null_mut(),
        )
    })?;
    napi::check_status!(unsafe { napi::sys::napi_is_arraybuffer(raw.env, backing, &mut private) })?;
    if !private {
        return Err(invalid(
            "Kasumi requires a Buffer with private ArrayBuffer backing",
        ));
    }
    Ok(())
}

fn private_buffer(value: Unknown<'_>) -> Result<BufferSlice<'_>> {
    validate_private_buffer(value)?;
    BufferSlice::from_unknown(value)
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
    let Some(key) = options.get_named_property::<Option<Unknown<'_>>>(field)? else {
        return Ok(None);
    };
    let key = private_buffer(key)?;
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
            let key = private_buffer(item.get_named_property("key")?)?;
            key_within_limit(&key)?;
            if key.len() > *bytes_left {
                return Err(invalid("Kasumi batch exceeds the byte limit"));
            }
            *bytes_left -= key.len();
            // A later JS property getter may detach or mutate earlier inputs.
            // Snapshot each slice before reading another user-controlled property.
            let key = key.to_vec();
            let value = if item.has_named_property("value")? {
                let value = private_buffer(item.get_named_property("value")?)?;
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
    fn read_value<'db>(db: &'db mut LiveDb, key: BufferSlice<'_>) -> Result<Option<&'db [u8]>> {
        key_within_limit(&key)?;
        db.get_ref(&key).map_err(|e| storage("get", e))
    }

    fn visit_range(
        &self,
        options: &Object<'_>,
        emit: impl FnMut(&[u8], &[u8]) -> io::Result<()>,
    ) -> Result<usize> {
        let limit: f64 = options.get_named_property("limit")?;
        if !limit.is_finite()
            || limit.trunc() != limit
            || !(0.0..=MAX_RANGE_ROWS as f64).contains(&limit)
        {
            return Err(invalid(format!(
                "limit must be an integer between 0 and {MAX_RANGE_ROWS}"
            )));
        }
        let start = optional_key(options, "start")?;
        let end = optional_key(options, "end")?;
        let start_exclusive: Option<bool> = options.get_named_property("startExclusive")?;
        let end_inclusive: Option<bool> = options.get_named_property("endInclusive")?;
        let reverse: Option<bool> = options.get_named_property("reverse")?;
        let lower = bound_from(start.as_deref(), !start_exclusive.unwrap_or(false));
        let upper = bound_from(end.as_deref(), end_inclusive.unwrap_or(false));
        let mut db = self.inner()?;
        if reverse.unwrap_or(false) {
            db.visit_reverse(lower, upper, limit as usize, emit)
        } else {
            db.visit_forward(lower, upper, limit as usize, emit)
        }
        .map_err(|e| storage("range", e))
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
    pub fn get<'a>(
        &self,
        env: Env,
        #[napi(ts_arg_type = "Buffer")] key: Unknown<'a>,
    ) -> Result<Option<BufferSlice<'a>>> {
        let mut db = self.inner()?;
        Self::read_value(&mut db, private_buffer(key)?)?
            .map(|bytes| {
                if bytes.len() <= SMALL_READ_BYTES {
                    BufferSlice::copy_from(&env, bytes)
                } else {
                    BufferSlice::from_data(&env, bytes.to_vec())
                }
            })
            .transpose()
    }

    /// Copy a present value into caller-owned storage when it fits.
    /// Return its complete byte length, or null for a missing key. A short destination is unchanged.
    #[napi]
    pub fn get_into(
        &self,
        #[napi(ts_arg_type = "Buffer")] key: Unknown<'_>,
        #[napi(ts_arg_type = "Buffer")] destination: Unknown<'_>,
    ) -> Result<Option<u32>> {
        validate_private_buffer(destination)?;
        // Finish borrowing the key before touching the destination. JS may pass overlapping views.
        let mut db = self.inner()?;
        let Some(value) = Self::read_value(&mut db, private_buffer(key)?)? else {
            return Ok(None);
        };
        let mut destination = BufferSlice::from_unknown(destination)?;
        if value.len() <= destination.len() {
            destination[..value.len()].copy_from_slice(value);
        }
        Ok(Some(value.len() as u32))
    }

    /// Bounds always describe ascending key space, including during reverse scans.
    #[napi]
    pub fn range(&self, options: Object<'_>) -> Result<Vec<RangeRow>> {
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
        self.visit_range(&options, emit)?;
        Ok(rows)
    }

    /// Return a bounded page of length-prefixed binary keys and values in one Buffer.
    /// Each field starts with its four-byte unsigned big-endian length.
    #[napi]
    pub fn range_packed<'a>(&self, env: Env, options: Object<'a>) -> Result<BufferSlice<'a>> {
        let mut page = Vec::new();
        self.visit_range(&options, |key, value| {
            packed::append_row(&mut page, key, value)
        })?;
        // A custom allocator can give reserve_exact more capacity than requested. Only the
        // visible bytes should be retained if that excess would cross the page limit.
        if page.capacity() > MAX_RANGE_BYTES {
            page = page.into_boxed_slice().into_vec();
        }
        BufferSlice::from_data(&env, page)
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
