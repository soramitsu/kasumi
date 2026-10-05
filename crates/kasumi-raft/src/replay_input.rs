//! Ordinary persisted encoded input from its SAME original point-read lease.
use crate::lifetime::RetainedStoragePlaintext;
use crate::{
    AdmittedApplicationInput, ApplicationPayload, Entry, InputBindingError, RaftCommand, TypeConfig,
};
use openraft::{EntryPayload, LogId};
use serde::{
    Deserialize, Deserializer,
    de::{self, EnumAccess, SeqAccess, VariantAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::{fmt, ops::Range, sync::Arc};

/// Fixed inline facts retain the named Store owner/control. No new Arc/Vec/token
/// is allocated here, and no original lease is extracted or duplicated.
#[derive(Clone)]
pub(crate) struct ReplayInput {
    original: RetainedStoragePlaintext,
    body: Range<usize>,
    log_id: LogId<u64>,
    digest: [u8; 32],
}
impl ReplayInput {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.original.as_bytes()[self.body.clone()]
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn is_from_memory(
        &self,
        provider: &Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    ) -> bool {
        self.original.is_from_memory(provider)
    }
    pub(crate) fn require_log_id(&self, id: LogId<u64>) -> Result<(), InputBindingError> {
        if self.log_id == id {
            Ok(())
        } else {
            Err(InputBindingError::Foreign)
        }
    }
}

struct BorrowedApplication<'a> {
    log_id: LogId<u64>,
    body: &'a [u8],
}
struct NormalApplication<'a>(&'a [u8]);
struct ApplicationBytes<'a>(&'a [u8]);

impl<'de> Deserialize<'de> for ApplicationBytes<'de> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct ApplicationVisitor;
        impl<'de> Visitor<'de> for ApplicationVisitor {
            type Value = ApplicationBytes<'de>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("ordinary Application bytes")
            }
            fn visit_enum<A: EnumAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
                let (kind, variant) = access.variant::<u32>()?;
                if kind != 0 {
                    return Err(de::Error::custom(
                        "raft application header has a different command variant",
                    ));
                }
                variant.newtype_variant::<&'de [u8]>().map(ApplicationBytes)
            }
        }
        decoder.deserialize_enum(
            "RaftCommand",
            &["Application", "Retirement", "Custody"],
            ApplicationVisitor,
        )
    }
}
impl<'de> Deserialize<'de> for NormalApplication<'de> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct NormalVisitor;
        impl<'de> Visitor<'de> for NormalVisitor {
            type Value = NormalApplication<'de>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("ordinary Normal entry")
            }
            fn visit_enum<A: EnumAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
                let (kind, variant) = access.variant::<u32>()?;
                if kind != 1 {
                    return Err(de::Error::custom(
                        "raft application header has a different payload variant",
                    ));
                }
                variant
                    .newtype_variant::<ApplicationBytes<'de>>()
                    .map(|value| NormalApplication(value.0))
            }
        }
        decoder.deserialize_enum(
            "EntryPayload",
            &["Blank", "Normal", "Membership"],
            NormalVisitor,
        )
    }
}
impl<'de> Deserialize<'de> for BorrowedApplication<'de> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct EntryVisitor;
        impl<'de> Visitor<'de> for EntryVisitor {
            type Value = BorrowedApplication<'de>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("current ordinary application log entry")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let log_id = sequence
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let body = sequence
                    .next_element::<NormalApplication<'de>>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?
                    .0;
                let initialization = sequence
                    .next_element::<Option<&'de [u8]>>()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                if initialization.is_some() {
                    return Err(de::Error::custom(
                        "initialization cause must be attached to the first membership entry",
                    ));
                }
                Ok(BorrowedApplication { log_id, body })
            }
        }
        decoder.deserialize_struct(
            "Entry",
            &["log_id", "payload", "initialization"],
            EntryVisitor,
        )
    }
}

pub(crate) fn decode_application_entry(
    original: &RetainedStoragePlaintext,
    format: &[u8],
) -> anyhow::Result<Entry<TypeConfig>> {
    use anyhow::{Context, ensure};
    let bytes = original.as_bytes();
    let body = bytes
        .strip_prefix(format)
        .context("unknown raft log record format")?;
    // Existing postcard::from_bytes trailing-byte behavior is retained. Header
    // validation still binds the ENTIRE original encoding/hash after this call.
    let decoded: BorrowedApplication<'_> =
        postcard::from_bytes(body).context("invalid binary raft log entry")?;
    // The controlled borrowed visitor supplies a slice of this SAME encoding.
    // Use checked scalar addresses/ranges; no stored self-reference or unsafe
    // lifetime extension is needed when the inline owner moves or is cloned.
    let start = (decoded.body.as_ptr() as usize)
        .checked_sub(bytes.as_ptr() as usize)
        .context("raft application range differs")?;
    let end = start
        .checked_add(decoded.body.len())
        .context("raft application range overflow")?;
    ensure!(
        end <= bytes.len() && &bytes[start..end] == decoded.body,
        "raft application range differs"
    );
    let input = ReplayInput {
        original: original.clone(),
        body: start..end,
        log_id: decoded.log_id,
        digest: Sha256::digest(decoded.body).into(),
    };
    Ok(Entry {
        log_id: decoded.log_id,
        payload: EntryPayload::Normal(RaftCommand::Application(
            ApplicationPayload::admitted_replay(AdmittedApplicationInput::from_replay(input)),
        )),
        initialization: None,
    })
}

#[cfg(test)]
#[path = "replay_input_tests.rs"]
mod tests;
