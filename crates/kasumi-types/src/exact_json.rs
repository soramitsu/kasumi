//! Exact current-writer JSON admission for bounded durable records. A decoded
//! equivalent spelling is never an accepted first-release record: whitespace,
//! reordered or duplicate keys, omitted defaults, escapes and trailing bytes
//! are rejected instead of being repaired by a later rewrite.
use anyhow::{Context, Result, bail, ensure};
use serde::{Serialize, de::DeserializeOwned};
use std::io::{self, Write};

/// Streams the current writer's encoding against the original bytes without a
/// second encoded buffer, stopping serialization at the first differing write.
struct Compare<'a> {
    remaining: &'a [u8],
    differs: bool,
}

impl Write for Compare<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(remaining) = self.remaining.strip_prefix(bytes) else {
            self.differs = true;
            return Err(io::Error::other("current writer bytes differ"));
        };
        self.remaining = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Require `original` to be exactly the bytes `serde_json::to_writer` produces
/// for `decoded`. The caller retains its physical byte bound before decoding.
/// A value the current writer cannot encode is an encoding failure, never a
/// claim about the original bytes.
pub fn require_current_writer_bytes<T: Serialize + ?Sized>(
    original: &[u8],
    decoded: &T,
    name: &str,
) -> Result<()> {
    let mut compare = Compare {
        remaining: original,
        differs: false,
    };
    match serde_json::to_writer(&mut compare, decoded) {
        Ok(()) => {}
        Err(_) if compare.differs => bail!("noncanonical {name}"),
        Err(error) => return Err(error).with_context(|| format!("{name} encoding failed")),
    }
    ensure!(compare.remaining.is_empty(), "noncanonical {name}");
    Ok(())
}

/// Bounded exact decode. The byte bound is checked before any parsing, then the
/// decoded value must re-encode to exactly `bytes` under the current writer.
pub fn decode_exact<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    max: usize,
    name: &str,
) -> Result<T> {
    ensure!(bytes.len() <= max, "{name} exceeds {max} bytes");
    let value: T = serde_json::from_slice(bytes).with_context(|| format!("invalid {name}"))?;
    require_current_writer_bytes(bytes, &value, name)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, CreateCredential, CredentialResource};
    use serde::{Deserialize, Deserializer};
    use std::{
        cell::Cell,
        collections::{BTreeMap, BTreeSet},
    };
    use uuid::Uuid;

    const NAME: &str = "credential request";
    const MAX: usize = 64 << 10;

    fn credential() -> CreateCredential {
        CreateCredential {
            family_id: Uuid::from_u128(7),
            principal: "admin".into(),
            tenant: "tenant".into(),
            resource: CredentialResource::Database {
                incarnation: Uuid::from_u128(9),
            },
            scopes: BTreeSet::from([Action::Read, Action::Admin]),
            lifetime_seconds: 3600,
        }
    }

    fn current() -> Vec<u8> {
        serde_json::to_vec(&credential()).unwrap()
    }

    fn noncanonical(bytes: &[u8]) -> bool {
        decode_exact::<CreateCredential>(bytes, MAX, NAME)
            .is_err_and(|error| format!("{error:#}") == format!("noncanonical {NAME}"))
    }

    fn text(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).unwrap()
    }

    #[test]
    fn current_writer_bytes_are_accepted_at_the_exact_bound() {
        let bytes = current();
        assert_eq!(
            decode_exact::<CreateCredential>(&bytes, bytes.len(), NAME).unwrap(),
            credential()
        );
        require_current_writer_bytes(&bytes, &credential(), NAME).unwrap();
        assert_eq!(
            decode_exact::<BTreeMap<String, u64>>(b"{}", 2, "map").unwrap(),
            BTreeMap::new()
        );
    }

    #[test]
    fn whitespace_and_escaped_spellings_are_noncanonical() {
        let bytes = current();
        let spaced = text(&bytes).replacen(':', ": ", 1);
        assert!(noncanonical(spaced.as_bytes()));
        let mut leading = b" ".to_vec();
        leading.extend_from_slice(&bytes);
        assert!(noncanonical(&leading));
        let mut newline = bytes.clone();
        newline.insert(1, b'\n');
        assert!(noncanonical(&newline));
        let escaped = text(&bytes).replacen("\"admin\"", "\"\\u0061dmin\"", 1);
        assert_ne!(escaped.as_bytes(), bytes.as_slice());
        assert!(noncanonical(escaped.as_bytes()));
    }

    #[test]
    fn reordered_keys_are_noncanonical() {
        let mut value = serde_json::to_value(credential()).unwrap();
        let object = value.as_object_mut().unwrap();
        let family = object.remove("family_id").unwrap();
        object.insert("family_id".into(), family);
        let reordered = serde_json::to_vec(&value).unwrap();
        assert_ne!(reordered, current());
        assert_eq!(
            serde_json::from_slice::<CreateCredential>(&reordered).unwrap(),
            credential()
        );
        assert!(noncanonical(&reordered));
    }

    #[test]
    fn omitted_default_field_is_noncanonical() {
        let mut value = serde_json::to_value(credential()).unwrap();
        value.as_object_mut().unwrap().remove("lifetime_seconds");
        let omitted = serde_json::to_vec(&value).unwrap();
        // Serde's default would silently restore the omitted field.
        assert_eq!(
            serde_json::from_slice::<CreateCredential>(&omitted).unwrap(),
            credential()
        );
        assert!(noncanonical(&omitted));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut whitespace = current();
        whitespace.extend_from_slice(b" \n");
        assert!(noncanonical(&whitespace));
        let mut value = current();
        value.extend_from_slice(b"{}");
        let error = decode_exact::<CreateCredential>(&value, MAX, NAME).unwrap_err();
        assert!(format!("{error:#}").starts_with(&format!("invalid {NAME}")));
        let bytes = current();
        let error = require_current_writer_bytes(&bytes[..bytes.len() - 1], &credential(), NAME)
            .unwrap_err();
        assert_eq!(format!("{error:#}"), format!("noncanonical {NAME}"));
    }

    #[test]
    fn duplicate_keys_never_collapse_into_an_accepted_record() {
        let bytes = current();
        let duplicated = text(&bytes).replacen(
            "\"principal\":\"admin\"",
            "\"principal\":\"other\",\"principal\":\"admin\"",
            1,
        );
        assert!(decode_exact::<CreateCredential>(duplicated.as_bytes(), MAX, NAME).is_err());
        let map = br#"{"a":1,"a":1}"#;
        assert_eq!(
            serde_json::from_slice::<BTreeMap<String, u64>>(map).unwrap(),
            BTreeMap::from([("a".to_owned(), 1)])
        );
        let error = decode_exact::<BTreeMap<String, u64>>(map, MAX, "map").unwrap_err();
        assert_eq!(format!("{error:#}"), "noncanonical map");
        let error = decode_exact::<serde_json::Value>(map, MAX, "value").unwrap_err();
        assert_eq!(format!("{error:#}"), "noncanonical value");
    }

    thread_local! {
        static DECODES: Cell<usize> = const { Cell::new(0) };
    }

    #[derive(Debug, Serialize)]
    struct Counted(String);

    impl<'de> Deserialize<'de> for Counted {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            DECODES.with(|count| count.set(count.get() + 1));
            String::deserialize(deserializer).map(Self)
        }
    }

    #[test]
    fn oversize_input_is_rejected_before_decode() {
        let bytes = serde_json::to_vec(&Counted("x".repeat(16))).unwrap();
        let before = DECODES.with(Cell::get);
        let error = decode_exact::<Counted>(&bytes, bytes.len() - 1, "counted").unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!("counted exceeds {} bytes", bytes.len() - 1)
        );
        assert_eq!(DECODES.with(Cell::get), before);
        assert_eq!(
            decode_exact::<Counted>(&bytes, bytes.len(), "counted")
                .unwrap()
                .0,
            "x".repeat(16)
        );
        assert_eq!(DECODES.with(Cell::get), before + 1);
    }

    #[test]
    fn current_writer_encoding_failure_is_not_reported_as_noncanonical() {
        let unencodable = BTreeMap::from([((1u8, 2u8), 3u8)]);
        let error = require_current_writer_bytes(b"{", &unencodable, "tuple map").unwrap_err();
        assert!(format!("{error:#}").starts_with("tuple map encoding failed"));
    }
}
