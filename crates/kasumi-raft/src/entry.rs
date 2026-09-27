//! Current native log entry. Only original first membership may carry a signed initialization cause.

use std::fmt;
use std::fmt::Debug;

use openraft::LogId;
use openraft::Membership;
use openraft::MessageSummary;
use openraft::RaftTypeConfig;
use openraft::log_id::RaftLogId;

use openraft::entry::{EntryPayload, FromAppData, RaftEntry, RaftPayload};

/// A Raft log entry.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(bound = "", deny_unknown_fields)]
pub struct Entry<C>
where
    C: RaftTypeConfig,
{
    pub log_id: LogId<C::NodeId>,

    /// This entry's payload.
    pub payload: EntryPayload<C>,

    /// Canonical bounded signed authority, attached before the first log is submitted.
    #[serde(deserialize_with = "required_initialization")]
    pub initialization: Option<Vec<u8>>,
}

impl<C> Clone for Entry<C>
where
    C: RaftTypeConfig,
    C::D: Clone,
{
    fn clone(&self) -> Self {
        Self {
            log_id: self.log_id.clone(),
            payload: self.payload.clone(),
            initialization: self.initialization.clone(),
        }
    }
}

impl<C> Debug for Entry<C>
where
    C: RaftTypeConfig,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("log_id", &self.log_id)
            .field("payload", &self.payload)
            .finish()
    }
}

impl<C> Default for Entry<C>
where
    C: RaftTypeConfig,
{
    fn default() -> Self {
        Self {
            log_id: LogId::default(),
            payload: EntryPayload::Blank,
            initialization: None,
        }
    }
}

impl<C> PartialEq for Entry<C>
where
    C::D: PartialEq,
    C: RaftTypeConfig,
{
    fn eq(&self, other: &Self) -> bool {
        self.log_id == other.log_id
            && self.payload == other.payload
            && self.initialization == other.initialization
    }
}

impl<C> AsRef<Entry<C>> for Entry<C>
where
    C: RaftTypeConfig,
{
    fn as_ref(&self) -> &Entry<C> {
        self
    }
}

impl<C> fmt::Display for Entry<C>
where
    C: RaftTypeConfig,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.log_id, self.payload.summary())
    }
}

impl<C> MessageSummary<Entry<C>> for Entry<C>
where
    C: RaftTypeConfig,
{
    fn summary(&self) -> String {
        format!("{}:{}", self.log_id, self.payload.summary())
    }
}

impl<C> RaftPayload<C::NodeId, C::Node> for Entry<C>
where
    C: RaftTypeConfig,
{
    fn is_blank(&self) -> bool {
        self.payload.is_blank()
    }

    fn get_membership(&self) -> Option<&Membership<C::NodeId, C::Node>> {
        self.payload.get_membership()
    }
}

impl<C> RaftLogId<C::NodeId> for Entry<C>
where
    C: RaftTypeConfig,
{
    fn get_log_id(&self) -> &LogId<C::NodeId> {
        &self.log_id
    }

    fn set_log_id(&mut self, log_id: &LogId<C::NodeId>) {
        self.log_id = log_id.clone();
    }
}

impl<C> RaftEntry<C::NodeId, C::Node> for Entry<C>
where
    C: RaftTypeConfig,
{
    fn new_blank(log_id: LogId<C::NodeId>) -> Self {
        Self {
            log_id,
            payload: EntryPayload::Blank,
            initialization: None,
        }
    }

    fn new_membership(log_id: LogId<C::NodeId>, m: Membership<C::NodeId, C::Node>) -> Self {
        Self {
            log_id,
            payload: EntryPayload::Membership(m),
            initialization: None,
        }
    }
}

impl<C> FromAppData<C::D> for Entry<C>
where
    C: RaftTypeConfig,
{
    fn from_app_data(d: C::D) -> Self {
        Entry {
            log_id: LogId::default(),
            payload: EntryPayload::Normal(d),
            initialization: None,
        }
    }
}

fn required_initialization<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    serde::Deserialize::deserialize(decoder)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_entry_requires_explicit_initialization_field_and_rejects_retired_command() {
        let entry = Entry::<crate::TypeConfig>::default();
        let mut json = serde_json::to_value(&entry).unwrap();
        assert!(serde_json::from_value::<Entry<crate::TypeConfig>>(json.clone()).is_ok());
        json.as_object_mut().unwrap().remove("initialization");
        assert!(serde_json::from_value::<Entry<crate::TypeConfig>>(json).is_err());
        assert!(
            serde_json::from_value::<crate::RaftCommand>(
                serde_json::json!({"InitializationAssociation": []})
            )
            .is_err()
        );
    }
}
