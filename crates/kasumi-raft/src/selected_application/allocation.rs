//! Conservative concrete serde ownership for the existing cursor/manifest DTOs.
//! The visitor has no owned fields; serde_json's escape scratch is separately
//! quoted before preflight. This is not a generic JSON allocation guarantee.
use anyhow::{Context, Result};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{collections::BTreeSet, fmt};

const ALLOWANCE: u64 = 64;
const FIXED: u64 = 16 << 10;
// The vendored arbitrary-precision deserializer emits this synthetic map key
// through Serde's bytes channel; literal JSON keys stay on its string channel.
const NUMBER_MARKER: &[u8] = b"$serde_json::private::Number";

pub(super) struct Quote {
    pub(super) peak: u64,
    pub(super) retained: u64,
}
#[derive(Default)]
struct Shape {
    nodes: u64,
    string_bytes: u64,
}
struct Seed<'a>(&'a mut Shape);
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.0.nodes = self
            .0
            .nodes
            .checked_add(1)
            .ok_or_else(|| de::Error::custom("selection shape overflow"))?;
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded canonical metadata record")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        self.visit_bytes(value.as_bytes())
    }
    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<(), E> {
        self.visit_str(value)
    }
    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<(), E> {
        // This is only shape accounting. The actual typed decoder continues to
        // distinguish the vendor's synthetic number marker from a literal key.
        self.0.string_bytes = self
            .0
            .string_bytes
            .checked_add(value.len() as u64)
            .ok_or_else(|| de::Error::custom("selection string quote overflow"))?;
        Ok(())
    }
    fn visit_borrowed_bytes<E: de::Error>(self, value: &'de [u8]) -> Result<(), E> {
        self.visit_bytes(value)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        while values.next_element_seed(Seed(&mut *self.0))?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        while values.next_key_seed(Seed(&mut *self.0))?.is_some() {
            values.next_value_seed(Seed(&mut *self.0))?;
        }
        Ok(())
    }
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .context("selection allocation quote overflow")
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b)
        .context("selection allocation quote overflow")
}
fn round(a: u64) -> Result<u64> {
    a.checked_next_power_of_two()
        .context("selection allocation quote overflow")
}

pub(super) fn preflight_bytes(wire_bytes: usize) -> Result<u64> {
    // Retained wire plus serde_json escape scratch including realloc overlap.
    add(mul(5, u64::try_from(wire_bytes)?)?, FIXED)
}

pub(super) fn decode_quote(bytes: &[u8]) -> Result<Quote> {
    let mut shape = Shape::default();
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    Seed(&mut shape).deserialize(&mut decoder)?;
    decoder.end()?;
    drop(decoder);
    quote_shape(shape, bytes.len())
}

fn quote_shape(shape: Shape, wire_bytes: usize) -> Result<Quote> {
    // Complete current shapes: StoredMembership owns Vec<BTreeSet<u64>> and
    // BTreeMap<u64, BasicNode { addr: String }>. Other cursor/manifest fields
    // are fixed scalars and Strings. Serde's externally tagged enum does not
    // collect an untagged Content tree. One full internal B=6 Rust BTree node
    // per input token overquotes every membership map/set insertion, including
    // duplicate fields/elements before canonical validation rejects them.
    let tree_node = add(
        round(add(
            mul(
                11,
                (std::mem::size_of::<u64>() + std::mem::size_of::<crate::BasicNode>()) as u64,
            )?,
            mul(16, std::mem::size_of::<usize>() as u64)?,
        )?)?,
        ALLOWANCE,
    )?;
    let vector_element = add(
        mul(4, std::mem::size_of::<BTreeSet<u64>>() as u64)?,
        ALLOWANCE,
    )?;
    let per_token = add(add(tree_node, vector_element)?, ALLOWANCE)?;
    let retained = add(
        add(mul(shape.nodes, per_token)?, mul(2, shape.string_bytes)?)?,
        FIXED,
    )?;
    // Original wire plus serde escape growth/realloc overlap during typed
    // decoding. Canonical re-encoding gets a separate exact-size preclaim after
    // typed decode; omitted fields can make that representation larger.
    // Unexpected::Str error text Debug-escapes at most six output bytes per
    // decoded UTF-8 byte (raw DEL is the tight ASCII case). The 32× term covers
    // that formatting chain and String growth/old+new overlap. Optional local
    // anyhow backtrace capture is not included in this buffer/diagnostic quote.
    let peak = add(
        retained,
        add(preflight_bytes(wire_bytes)?, mul(32, shape.string_bytes)?)?,
    )?;
    Ok(Quote { peak, retained })
}

struct Counter(u64);
impl std::io::Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len() as u64)
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn canonical_bytes(value: &impl serde::Serialize) -> Result<u64> {
    let mut count = Counter(0);
    serde_json::to_writer(&mut count, value)?;
    Ok(count.0)
}

pub(super) fn encode_workspace(wire_bytes: usize, encoded_bytes: u64) -> Result<u64> {
    // serde_json::to_vec starts at 128 and Vec doubling/reallocation can have
    // old+new backing live. Count actual typed output before making this claim.
    add(
        u64::try_from(wire_bytes)?,
        add(mul(4, encoded_bytes.max(128))?, FIXED)?,
    )
}

// Private closed set of actual decoded metadata types. These quotes are only
// used after our own canonical decoder, never to adopt caller-owned capacity.
pub(super) trait RetainedMetadata {
    fn retained_bytes(&self) -> Result<u64>;
}
fn backing(bytes: u64) -> Result<u64> {
    if bytes == 0 {
        Ok(0)
    } else {
        add(round(bytes)?, ALLOWANCE)
    }
}
fn string(value: &String) -> Result<u64> {
    backing(value.capacity() as u64)
}
fn tree(entries: usize, key: usize, value: usize) -> Result<u64> {
    if entries == 0 {
        return Ok(0);
    }
    // Pinned Rust B=6: every non-root node contains at least five keys;
    // a nonempty root contains at least one. Charge a full internal node for
    // every possible node (including leaves), with fixed allocator allowance.
    let nodes = 1 + (entries as u64 - 1) / 5;
    let node = backing(add(
        mul(11, (key + value) as u64)?,
        mul(16, std::mem::size_of::<usize>() as u64)?,
    )?)?;
    mul(nodes, node)
}
fn membership(value: &crate::StoredMembership<u64, crate::BasicNode>) -> Result<u64> {
    let membership = value.membership();
    let configs = membership.get_joint_config();
    let mut bytes = backing(mul(
        configs.capacity() as u64,
        std::mem::size_of::<BTreeSet<u64>>() as u64,
    )?)?;
    for config in configs {
        bytes = add(bytes, tree(config.len(), std::mem::size_of::<u64>(), 0)?)?;
    }
    let mut nodes = 0usize;
    for (_, node) in membership.nodes() {
        nodes = nodes
            .checked_add(1)
            .context("selection membership count overflow")?;
        bytes = add(bytes, string(&node.addr)?)?;
    }
    add(
        bytes,
        tree(
            nodes,
            std::mem::size_of::<u64>(),
            std::mem::size_of::<crate::BasicNode>(),
        )?,
    )
}
fn meta(value: &crate::SnapshotMeta<u64, crate::BasicNode>) -> Result<u64> {
    add(
        membership(&value.last_membership)?,
        string(&value.snapshot_id)?,
    )
}
impl RetainedMetadata for String {
    fn retained_bytes(&self) -> Result<u64> {
        string(self)
    }
}
impl RetainedMetadata for kasumi_store::ApplicationBootstrapManifest {
    fn retained_bytes(&self) -> Result<u64> {
        string(&self.digest)
    }
}
impl RetainedMetadata for crate::storage::SnapshotManifest {
    fn retained_bytes(&self) -> Result<u64> {
        add(string(&self.sha256)?, string(&self.id)?)
    }
}
impl RetainedMetadata for crate::storage::SnapshotCoverage {
    fn retained_bytes(&self) -> Result<u64> {
        add(
            add(string(&self.manifest_id)?, string(&self.snapshot_sha256)?)?,
            add(string(&self.backend_sha256)?, meta(&self.meta)?)?,
        )
    }
}
impl RetainedMetadata for crate::control::AppliedCursor {
    fn retained_bytes(&self) -> Result<u64> {
        match self {
            Self::Entry(position) => add(
                membership(&position.membership)?,
                string(&position.command_sha256)?,
            ),
            Self::Snapshot {
                meta: value,
                backend_sha256,
                snapshot_sha256,
            } => add(
                meta(value)?,
                add(string(backend_sha256)?, string(snapshot_sha256)?)?,
            ),
        }
    }
}

// Match the pinned serde_json parse_any_number split without allocating its
// temporary String: in-range integers visit a scalar, while decimals, exponents
// and oversized integers visit a synthetic map with one key and String value.
fn quote_scalar(shape: &mut Shape, bytes: &[u8]) -> Result<()> {
    shape.nodes = add(shape.nodes, 1)?;
    if matches!(bytes.first(), Some(b'-' | b'0'..=b'9')) {
        let text = std::str::from_utf8(bytes).context("selection scalar is not UTF-8")?;
        let inline = if bytes[0] == b'-' {
            text.parse::<i64>().is_ok()
        } else {
            text.parse::<u64>().is_ok()
        };
        if !inline {
            shape.nodes = add(shape.nodes, 2)?;
            shape.string_bytes = add(
                shape.string_bytes,
                add(NUMBER_MARKER.len() as u64, bytes.len() as u64)?,
            )?;
        }
    }
    Ok(())
}

/// Allocation-free shape upper bound for producer/selected canonical wire.
/// Count JSON value/key tokens plus the vendored arbitrary-number map channel;
/// wire string bytes overquote decoded UTF-8 bytes. This does not validate JSON,
/// canonical identity, or schema; the actual selected decoder still does that.
pub(super) fn canonical_wire_quote(bytes: &[u8]) -> Result<Quote> {
    let mut shape = Shape::default();
    let mut string = false;
    let mut escaped = false;
    let mut scalar = None;
    for (index, &byte) in bytes.iter().enumerate() {
        if string {
            if byte == b'"' && !escaped {
                string = false;
                continue;
            }
            shape.string_bytes = add(shape.string_bytes, 1)?;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            }
            continue;
        }
        if matches!(
            byte,
            b'"' | b'{' | b'[' | b'}' | b']' | b',' | b':' | b' ' | b'\n' | b'\r' | b'\t'
        ) && let Some(start) = scalar.take()
        {
            quote_scalar(&mut shape, &bytes[start..index])?;
        }
        match byte {
            b'"' => {
                shape.nodes = add(shape.nodes, 1)?;
                string = true;
            }
            b'{' | b'[' => shape.nodes = add(shape.nodes, 1)?,
            b'}' | b']' | b',' | b':' | b' ' | b'\n' | b'\r' | b'\t' => {}
            _ => {
                scalar.get_or_insert(index);
            }
        }
    }
    if let Some(start) = scalar {
        quote_scalar(&mut shape, &bytes[start..])?;
    }
    anyhow::ensure!(!string && !escaped, "truncated selection plan string");
    quote_shape(shape, bytes.len())
}

/// The same canonical-wire shape quote, streamed from the actual borrowed DTO.
/// No encoded buffer or cloned membership is created merely to size a source.
pub(super) fn serialized_quote(value: &impl serde::Serialize) -> Result<(usize, Quote, [u8; 32])> {
    use sha2::Digest;
    struct Scalar {
        bytes: u64,
        numeric: bool,
        negative: bool,
        integer: bool,
        magnitude: Option<u64>,
    }
    impl Scalar {
        fn new(first: u8) -> Self {
            Self {
                bytes: 0,
                numeric: matches!(first, b'-' | b'0'..=b'9'),
                negative: first == b'-',
                integer: true,
                magnitude: Some(0),
            }
        }
        fn push(&mut self, byte: u8) -> Result<()> {
            if byte.is_ascii_digit() {
                self.magnitude = self
                    .magnitude
                    .and_then(|value| value.checked_mul(10))
                    .and_then(|value| value.checked_add((byte - b'0') as u64));
            } else if !(self.bytes == 0 && byte == b'-') {
                self.integer = false;
            }
            self.bytes = add(self.bytes, 1)?;
            Ok(())
        }
        fn finish(self, shape: &mut Shape) -> Result<()> {
            shape.nodes = add(shape.nodes, 1)?;
            let inline = self.integer
                && self
                    .magnitude
                    .is_some_and(|value| !self.negative || value <= (i64::MAX as u64) + 1);
            if self.numeric && !inline {
                shape.nodes = add(shape.nodes, 2)?;
                shape.string_bytes = add(
                    shape.string_bytes,
                    add(NUMBER_MARKER.len() as u64, self.bytes)?,
                )?;
            }
            Ok(())
        }
    }
    struct Wire {
        shape: Shape,
        hash: sha2::Sha256,
        bytes: usize,
        string: bool,
        escaped: bool,
        scalar: Option<Scalar>,
    }
    impl Wire {
        fn push(&mut self, bytes: &[u8]) -> Result<()> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .context("selection serialized quote overflow")?;
            self.hash.update(bytes);
            for &byte in bytes {
                if self.string {
                    if byte == b'"' && !self.escaped {
                        self.string = false;
                        continue;
                    }
                    self.shape.string_bytes = add(self.shape.string_bytes, 1)?;
                    self.escaped = !self.escaped && byte == b'\\';
                    continue;
                }
                if matches!(
                    byte,
                    b'"' | b'{' | b'[' | b'}' | b']' | b',' | b':' | b' ' | b'\n' | b'\r' | b'\t'
                ) && let Some(scalar) = self.scalar.take()
                {
                    scalar.finish(&mut self.shape)?;
                }
                match byte {
                    b'"' => {
                        self.shape.nodes = add(self.shape.nodes, 1)?;
                        self.string = true;
                    }
                    b'{' | b'[' => self.shape.nodes = add(self.shape.nodes, 1)?,
                    b'}' | b']' | b',' | b':' | b' ' | b'\n' | b'\r' | b'\t' => {}
                    _ => self
                        .scalar
                        .get_or_insert_with(|| Scalar::new(byte))
                        .push(byte)?,
                }
            }
            Ok(())
        }
    }
    impl std::io::Write for Wire {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.push(bytes).map_err(std::io::Error::other)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut wire = Wire {
        shape: Shape::default(),
        hash: sha2::Sha256::new(),
        bytes: 0,
        string: false,
        escaped: false,
        scalar: None,
    };
    serde_json::to_writer(&mut wire, value)?;
    if let Some(scalar) = wire.scalar.take() {
        scalar.finish(&mut wire.shape)?;
    }
    anyhow::ensure!(
        !wire.string && !wire.escaped,
        "truncated serialized selection shape"
    );
    Ok((
        wire.bytes,
        quote_shape(wire.shape, wire.bytes)?,
        wire.hash.finalize().into(),
    ))
}
