//! First-release deployment schema preflight.
//!
//! This recognizes the current writer's field order and JSON grammar without
//! allocating. It inventories collection cardinalities and decoded string
//! bytes before Serde decode. It does not bound the derived typed allocations.

const MAX_DEPTH: usize = 16;
const MAX_CONTROL_NODES: u64 = 1024;
const MAX_CONTROL_TENANTS: u64 = 100_000;
const MAX_CONTROL_PARTITIONS: u64 = 1024;

// String map keys and string-set members are ordered by decoded UTF-8 bytes in
// Rust's BTreeMap/BTreeSet. Comparing raw JSON bytes would misorder escapes.
struct Decoded<'a> {
    encoded: &'a [u8],
    offset: usize,
    pending: [u8; 4],
    pending_len: usize,
    pending_at: usize,
}
impl<'a> Decoded<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self {
            encoded,
            offset: 0,
            pending: [0; 4],
            pending_len: 0,
            pending_at: 0,
        }
    }
    fn hex4(&mut self) -> u16 {
        let mut number = 0_u16;
        for _ in 0..4 {
            let byte = self.encoded[self.offset];
            self.offset += 1;
            let digit = (byte as char)
                .to_digit(16)
                .expect("prevalidated JSON escape");
            number = (number << 4) | digit as u16;
        }
        number
    }
}
impl Iterator for Decoded<'_> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pending_at < self.pending_len {
            let byte = self.pending[self.pending_at];
            self.pending_at += 1;
            return Some(byte);
        }
        let byte = *self.encoded.get(self.offset)?;
        self.offset += 1;
        if byte != b'\\' {
            return Some(byte);
        }
        let escaped = self.encoded[self.offset];
        self.offset += 1;
        let byte = match escaped {
            b'"' | b'\\' | b'/' => escaped,
            b'b' => 8,
            b'f' => 12,
            b'n' => 10,
            b'r' => 13,
            b't' => 9,
            b'u' => {
                let first = self.hex4();
                let scalar = if (0xD800..=0xDBFF).contains(&first) {
                    self.offset += 2; // The prevalidated second escape is `\u`.
                    let second = self.hex4();
                    0x10000 + (((first - 0xD800) as u32) << 10) + (second - 0xDC00) as u32
                } else {
                    first as u32
                };
                self.pending_len = char::from_u32(scalar)
                    .expect("prevalidated JSON scalar")
                    .encode_utf8(&mut self.pending)
                    .len();
                self.pending_at = 1;
                return Some(self.pending[0]);
            }
            _ => unreachable!("prevalidated JSON escape"),
        };
        Some(byte)
    }
}

fn greater_decoded(previous: &[u8], current: &[u8]) -> bool {
    Decoded::new(previous).cmp(Decoded::new(current)).is_lt()
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Inventory {
    pub encoded_bytes: u64,
    pub decoded_string_bytes: u64,
    pub strings: u64,
    pub object_entries: u64,
    pub array_entries: u64,
    pub grants: u64,
    pub voters: u64,
    pub control_nodes: u64,
    pub control_tenants: u64,
    pub lifecycle_partitions: u64,
    pub max_depth: usize,
}

pub fn inspect_current_deployment(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<Inventory, &'static str> {
    if bytes.len() > max_bytes {
        return Err("deployment exceeds paired writer byte bound");
    }
    // Raw JSON must be UTF-8. Escaped code points are checked separately.
    std::str::from_utf8(bytes).map_err(|_| "deployment is not UTF-8")?;
    let mut parser = Parser {
        bytes,
        pos: 0,
        result: Inventory {
            encoded_bytes: u64::try_from(bytes.len())
                .map_err(|_| "deployment byte length overflow")?,
            ..Inventory::default()
        },
    };
    parser.open(b'[', 1)?;
    parser.literal_string(b"replicated")?;
    parser.comma()?;
    parser.bootstrap()?;
    parser.close(b']')?;
    if parser.pos != bytes.len() {
        return Err("trailing deployment bytes");
    }
    Ok(parser.result)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    result: Inventory,
}

impl<'a> Parser<'a> {
    fn at(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
    fn byte(&mut self, expected: u8) -> Result<(), &'static str> {
        if self.at() != Some(expected) {
            return Err("unexpected deployment token");
        }
        self.pos += 1;
        Ok(())
    }
    fn comma(&mut self) -> Result<(), &'static str> {
        self.byte(b',')
    }
    fn colon(&mut self) -> Result<(), &'static str> {
        self.byte(b':')
    }
    fn open(&mut self, byte: u8, depth: usize) -> Result<(), &'static str> {
        if depth > MAX_DEPTH {
            return Err("deployment nesting exceeds fixed bound");
        }
        self.byte(byte)?;
        self.result.max_depth = self.result.max_depth.max(depth);
        Ok(())
    }
    fn close(&mut self, byte: u8) -> Result<(), &'static str> {
        self.byte(byte)
    }
    fn add(counter: &mut u64) -> Result<(), &'static str> {
        *counter = counter
            .checked_add(1)
            .ok_or("deployment inventory overflow")?;
        Ok(())
    }
    fn field(&mut self, key: &[u8]) -> Result<(), &'static str> {
        self.literal_string(key)?;
        Self::add(&mut self.result.object_entries)?;
        self.colon()
    }
    fn literal_string(&mut self, expected: &[u8]) -> Result<(), &'static str> {
        if self.string()? != expected {
            return Err("unsupported deployment field or enum");
        }
        Ok(())
    }
    fn string(&mut self) -> Result<&'a [u8], &'static str> {
        self.byte(b'"')?;
        let start = self.pos;
        let mut decoded = 0_u64;
        loop {
            let byte = self.at().ok_or("truncated deployment string")?;
            if byte == b'"' {
                let end = self.pos;
                self.pos += 1;
                Self::add(&mut self.result.strings)?;
                self.result.decoded_string_bytes = self
                    .result
                    .decoded_string_bytes
                    .checked_add(decoded)
                    .ok_or("decoded string inventory overflow")?;
                return Ok(&self.bytes[start..end]);
            }
            if byte < 0x20 {
                return Err("unescaped JSON control byte");
            }
            self.pos += 1;
            if byte != b'\\' {
                decoded = decoded
                    .checked_add(1)
                    .ok_or("decoded string inventory overflow")?;
                continue;
            }
            let escape = self.at().ok_or("truncated JSON escape")?;
            self.pos += 1;
            match escape {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                    decoded = decoded
                        .checked_add(1)
                        .ok_or("decoded string inventory overflow")?;
                }
                b'u' => {
                    let first = self.hex4()?;
                    let scalar = if (0xD800..=0xDBFF).contains(&first) {
                        self.byte(b'\\')?;
                        self.byte(b'u')?;
                        let second = self.hex4()?;
                        if !(0xDC00..=0xDFFF).contains(&second) {
                            return Err("invalid JSON surrogate pair");
                        }
                        0x10000 + (((first - 0xD800) as u32) << 10) + (second - 0xDC00) as u32
                    } else {
                        if (0xDC00..=0xDFFF).contains(&first) {
                            return Err("orphan JSON low surrogate");
                        }
                        first as u32
                    };
                    let width = char::from_u32(scalar)
                        .ok_or("invalid JSON Unicode scalar")?
                        .len_utf8() as u64;
                    decoded = decoded
                        .checked_add(width)
                        .ok_or("decoded string inventory overflow")?;
                }
                _ => return Err("invalid JSON escape"),
            }
        }
    }
    fn hex4(&mut self) -> Result<u16, &'static str> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let byte = self.at().ok_or("truncated JSON Unicode escape")?;
            self.pos += 1;
            let digit = (byte as char)
                .to_digit(16)
                .ok_or("invalid JSON Unicode escape")?;
            value = (value << 4) | digit as u16;
        }
        Ok(value)
    }
    fn number(&mut self) -> Result<u64, &'static str> {
        let first = self.at().ok_or("missing deployment integer")?;
        if !first.is_ascii_digit() {
            return Err("deployment integer must be unsigned");
        }
        self.pos += 1;
        let mut value = u64::from(first - b'0');
        if first == b'0' && self.at().is_some_and(|next| next.is_ascii_digit()) {
            return Err("noncanonical leading zero");
        }
        while let Some(byte) = self.at() {
            if !byte.is_ascii_digit() {
                break;
            }
            value = value
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(byte - b'0')))
                .ok_or("deployment integer overflow")?;
            self.pos += 1;
        }
        Ok(value)
    }
    fn boolean(&mut self) -> Result<(), &'static str> {
        if self.bytes[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(())
        } else if self.bytes[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(())
        } else {
            Err("expected deployment boolean")
        }
    }
    fn nullable_string(&mut self) -> Result<(), &'static str> {
        if self.bytes[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(())
        } else {
            self.string().map(|_| ())
        }
    }
    fn bootstrap(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 2)?;
        self.field(b"genesis")?;
        self.genesis()?;
        self.comma()?;
        self.field(b"incarnation")?;
        self.string()?;
        self.comma()?;
        self.field(b"initial_policy")?;
        self.policy()?;
        self.comma()?;
        self.field(b"initial_limits")?;
        let max_grants = self.limits()?;
        self.comma()?;
        self.field(b"voters")?;
        self.voters()?;
        self.close(b'}')?;
        if self.result.grants > max_grants {
            return Err("deployment grant quota exceeded");
        }
        Ok(())
    }
    fn genesis(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 3)?;
        self.field(b"kind")?;
        let kind = self.string()?;
        match kind {
            b"application" => self.close(b'}'),
            b"control" => {
                self.comma()?;
                self.field(b"control")?;
                self.control()?;
                self.close(b'}')
            }
            _ => Err("unsupported replicated genesis kind"),
        }
    }
    fn control(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 4)?;
        self.field(b"topology")?;
        self.topology()?;
        self.comma()?;
        self.field(b"lifecycle")?;
        self.lifecycle()?;
        self.close(b'}')
    }
    fn topology(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 5)?;
        self.field(b"nodes")?;
        self.nodes()?;
        self.comma()?;
        self.field(b"tenants")?;
        self.tenants()?;
        self.close(b'}')
    }
    fn numeric_key(&mut self, previous: &mut u64) -> Result<(), &'static str> {
        let raw = self.string()?;
        if raw.is_empty() || raw[0] == b'0' || !raw.iter().all(u8::is_ascii_digit) {
            return Err("invalid numeric map key");
        }
        let mut value = 0_u64;
        for &digit in raw {
            value = value
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(digit - b'0')))
                .ok_or("numeric map key overflow")?;
        }
        if value <= *previous {
            return Err("numeric map keys not strictly ordered");
        }
        *previous = value;
        Self::add(&mut self.result.object_entries)?;
        self.colon()
    }
    fn nodes(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 6)?;
        let mut previous = 0;
        while self.at() != Some(b'}') {
            if previous != 0 {
                self.comma()?;
            }
            self.numeric_key(&mut previous)?;
            Self::add(&mut self.result.control_nodes)?;
            if self.result.control_nodes > MAX_CONTROL_NODES {
                return Err("too many Control nodes");
            }
            self.control_node()?;
        }
        self.close(b'}')
    }
    fn control_node(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 7)?;
        self.field(b"endpoint")?;
        self.string()?;
        self.comma()?;
        self.field(b"failure_domain")?;
        self.string()?;
        self.comma()?;
        self.field(b"certificate_pins")?;
        self.open(b'[', 8)?;
        let mut pins = 0;
        let mut previous_pin: Option<&[u8]> = None;
        while self.at() != Some(b']') {
            if pins > 0 {
                self.comma()?;
            }
            let pin = self.string()?;
            if previous_pin.is_some_and(|prior| !greater_decoded(prior, pin)) {
                return Err("Control certificate pins not strictly ordered");
            }
            previous_pin = Some(pin);
            Self::add(&mut self.result.array_entries)?;
            pins += 1;
            if pins > 2 {
                return Err("too many Control certificate pins");
            }
        }
        self.close(b']')?;
        self.close(b'}')
    }
    fn tenants(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 6)?;
        let mut previous_tenant: Option<&[u8]> = None;
        while self.at() != Some(b'}') {
            if self.result.control_tenants > 0 {
                self.comma()?;
            }
            let tenant = self.string()?;
            if previous_tenant.is_some_and(|prior| !greater_decoded(prior, tenant)) {
                return Err("Control tenant keys not strictly ordered");
            }
            previous_tenant = Some(tenant);
            Self::add(&mut self.result.object_entries)?;
            self.colon()?;
            Self::add(&mut self.result.control_tenants)?;
            if self.result.control_tenants > MAX_CONTROL_TENANTS {
                return Err("too many Control tenants");
            }
            self.route()?;
        }
        self.close(b'}')
    }
    fn route(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 7)?;
        self.field(b"incarnation")?;
        self.string()?;
        self.comma()?;
        self.field(b"mode")?;
        match self.string()? {
            b"local" | b"replicated" => (),
            _ => return Err("invalid deployment mode"),
        }
        self.comma()?;
        self.field(b"voters")?;
        self.numeric_set(8, 3)?;
        self.close(b'}')
    }
    fn numeric_set(&mut self, depth: usize, max: u64) -> Result<(), &'static str> {
        self.open(b'[', depth)?;
        let mut previous = 0_u64;
        let mut count = 0_u64;
        while self.at() != Some(b']') {
            if count > 0 {
                self.comma()?;
            }
            let id = self.number()?;
            if id == 0 || id <= previous {
                return Err("numeric set not strictly ordered");
            }
            previous = id;
            count += 1;
            if count > max {
                return Err("numeric set exceeds schema limit");
            }
            Self::add(&mut self.result.array_entries)?;
        }
        self.close(b']')
    }
    fn lifecycle(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 5)?;
        self.field(b"kind")?;
        match self.string()? {
            b"disabled" => self.close(b'}'),
            b"installed" => {
                self.comma()?;
                self.field(b"command_id")?;
                self.string()?;
                self.comma()?;
                self.field(b"installation")?;
                self.installation()?;
                self.close(b'}')
            }
            _ => Err("unsupported Control lifecycle kind"),
        }
    }
    fn installation(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 6)?;
        self.field(b"root")?;
        self.open(b'{', 7)?;
        self.field(b"control_incarnation")?;
        self.string()?;
        self.comma()?;
        self.field(b"public_key")?;
        self.string()?;
        self.close(b'}')?;
        self.comma()?;
        self.field(b"generation")?;
        self.number()?;
        self.comma()?;
        self.field(b"partitions")?;
        self.partitions()?;
        self.comma()?;
        for name in [
            b"max_intents".as_slice(),
            b"max_changes",
            b"max_state_bytes",
        ] {
            self.field(name)?;
            self.number()?;
            if name != b"max_state_bytes" {
                self.comma()?;
            }
        }
        self.close(b'}')
    }
    fn partitions(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 7)?;
        let mut previous_partition: Option<&[u8]> = None;
        while self.at() != Some(b'}') {
            if self.result.lifecycle_partitions > 0 {
                self.comma()?;
            }
            let partition = self.string()?;
            if previous_partition.is_some_and(|prior| !greater_decoded(prior, partition)) {
                return Err("lifecycle partition keys not strictly ordered");
            }
            previous_partition = Some(partition);
            Self::add(&mut self.result.object_entries)?;
            self.colon()?;
            Self::add(&mut self.result.lifecycle_partitions)?;
            if self.result.lifecycle_partitions > MAX_CONTROL_PARTITIONS {
                return Err("too many lifecycle partitions");
            }
            self.partition()?;
        }
        self.close(b'}')
    }
    fn partition(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 8)?;
        self.field(b"authority_id")?;
        self.string()?;
        self.comma()?;
        self.field(b"manifest_sha256")?;
        self.string()?;
        self.comma()?;
        self.field(b"partition")?;
        self.number()?;
        self.comma()?;
        self.field(b"signing_public_key")?;
        self.string()?;
        self.comma()?;
        self.field(b"maximum_lifetime_ms")?;
        self.number()?;
        self.comma()?;
        self.field(b"drain_ms")?;
        self.number()?;
        self.close(b'}')
    }
    fn policy(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 3)?;
        self.field(b"grants")?;
        self.open(b'[', 4)?;
        while self.at() != Some(b']') {
            if self.result.grants > 0 {
                self.comma()?;
            }
            Self::add(&mut self.result.grants)?;
            Self::add(&mut self.result.array_entries)?;
            self.grant()?;
        }
        self.close(b']')?;
        self.comma()?;
        self.field(b"strict_read_audit")?;
        self.boolean()?;
        self.close(b'}')
    }
    fn grant(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 5)?;
        self.field(b"principal")?;
        self.string()?;
        self.comma()?;
        self.field(b"collection")?;
        self.nullable_string()?;
        self.comma()?;
        self.field(b"actions")?;
        self.open(b'[', 6)?;
        let mut count = 0;
        let mut last_rank: Option<u8> = None;
        while self.at() != Some(b']') {
            if count > 0 {
                self.comma()?;
            }
            let rank = match self.string()? {
                b"read" => 0,
                b"write" => 1,
                b"admin" => 2,
                b"audit" => 3,
                _ => return Err("unsupported policy action"),
            };
            if last_rank.is_some_and(|prior| rank <= prior) {
                return Err("policy actions not strictly ordered");
            }
            last_rank = Some(rank);
            count += 1;
            if count > 4 {
                return Err("too many policy actions");
            }
            Self::add(&mut self.result.array_entries)?;
        }
        self.close(b']')?;
        self.close(b'}')
    }
    fn limits(&mut self) -> Result<u64, &'static str> {
        self.open(b'{', 3)?;
        self.field(b"history")?;
        self.number_object(
            4,
            &[
                b"max_feed_events",
                b"max_feed_bytes",
                b"max_archive_segments",
            ],
        )?;
        self.comma()?;
        self.field(b"atomic")?;
        self.number_object(
            4,
            &[
                b"max_operations",
                b"max_read_assertions",
                b"max_transaction_bytes",
                b"max_active_transactions",
                b"max_reserved_staging_bytes",
                b"max_permanent_staged_bytes",
                b"max_snapshot_leases",
                b"max_snapshot_lease_bytes",
            ],
        )?;
        self.comma()?;
        let before = [
            b"max_document_bytes".as_slice(),
            b"max_batch_operations",
            b"max_batch_bytes",
            b"max_documents",
            b"max_collections",
            b"max_schema_bytes",
            b"max_schema_activation_bytes",
            b"max_retirement_bytes",
            b"max_target_resolution_bytes",
            b"max_backup_binding_bytes",
        ];
        for name in before {
            self.field(name)?;
            self.number()?;
            self.comma()?;
        }
        self.field(b"max_policy_grants")?;
        let max_grants = self.number()?;
        self.comma()?;
        for name in [
            b"max_logical_bytes".as_slice(),
            b"max_snapshot_bytes",
            b"max_mutation_receipt_bytes",
        ] {
            self.field(name)?;
            self.number()?;
            self.comma()?;
        }
        self.field(b"audit_retention")?;
        self.number_object(4, &[b"hot_bytes", b"archive_bytes"])?;
        self.comma()?;
        let after = [
            b"max_query_candidates".as_slice(),
            b"max_query_groups",
            b"max_result_bytes",
            b"max_page_size",
            b"max_cursors",
            b"max_cursor_bytes",
            b"cursor_ttl_ms",
        ];
        for (index, name) in after.into_iter().enumerate() {
            self.field(name)?;
            self.number()?;
            if index + 1 != after.len() {
                self.comma()?;
            }
        }
        self.close(b'}')?;
        Ok(max_grants)
    }
    fn number_object(&mut self, depth: usize, fields: &[&[u8]]) -> Result<(), &'static str> {
        self.open(b'{', depth)?;
        for (index, name) in fields.iter().enumerate() {
            self.field(name)?;
            self.number()?;
            if index + 1 != fields.len() {
                self.comma()?;
            }
        }
        self.close(b'}')
    }
    fn voters(&mut self) -> Result<(), &'static str> {
        self.open(b'{', 3)?;
        let mut previous = 0;
        while self.at() != Some(b'}') {
            if self.result.voters > 0 {
                self.comma()?;
            }
            self.numeric_key(&mut previous)?;
            Self::add(&mut self.result.voters)?;
            if self.result.voters > 3 {
                return Err("more than three initial voters");
            }
            self.open(b'{', 4)?;
            self.field(b"address")?;
            self.string()?;
            self.comma()?;
            self.field(b"failure_domain")?;
            self.string()?;
            self.close(b'}')?;
        }
        self.close(b'}')?;
        if self.result.voters != 3 {
            return Err("exactly three initial voters required");
        }
        Ok(())
    }
}
