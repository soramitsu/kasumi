//! The selected immutable lifecycle history prefix. The source is installed only
//! after the engine has verified the corresponding namespace or snapshot.
use crate::{Error, LifecycleIntent, Result, staged_digest};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleIntentHead {
    pub count: u64,
    pub encoded_bytes: u64,
    pub revision: u64,
    pub sha256: String,
}

impl LifecycleIntentHead {
    pub fn empty(incarnation: Uuid) -> Result<Self> {
        Ok(Self {
            count: 0,
            encoded_bytes: 0,
            revision: 0,
            sha256: staged_digest(&("kasumi.lifecycle-intent-root.v1", incarnation))?.0,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleIntentRow {
    pub ordinal: u64,
    pub previous_sha256: String,
    pub command_sha256: String,
    pub intent: LifecycleIntent,
}

/// The decoded DTO is dropped before its original installed memory reservation.
pub struct LifecycleIntentRowLoan {
    pub row: Box<LifecycleIntentRow>,
    _retained: Box<dyn Send + Sync>,
}
impl LifecycleIntentRowLoan {
    pub fn new(row: LifecycleIntentRow, retained: Box<dyn Send + Sync>) -> Self {
        Self {
            row: Box::new(row),
            _retained: retained,
        }
    }
}
impl std::ops::Deref for LifecycleIntentRowLoan {
    type Target = LifecycleIntentRow;
    fn deref(&self) -> &Self::Target {
        &self.row
    }
}

pub enum LifecycleIntentLoan<'a> {
    Legacy(&'a LifecycleIntent),
    Selected(LifecycleIntentRowLoan),
}
impl std::ops::Deref for LifecycleIntentLoan<'_> {
    type Target = LifecycleIntent;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Legacy(value) => value,
            Self::Selected(value) => &value.intent,
        }
    }
}
/// A reader bound to one immutable namespace. The caller always supplies the
/// generation's selected prefix, including when several readers share storage.
pub trait LifecycleIntentRows: Send + Sync {
    fn point(
        &self,
        head: &LifecycleIntentHead,
        id: Uuid,
        max_intent_bytes: usize,
    ) -> Result<Option<LifecycleIntentRowLoan>>;
    fn row(
        &self,
        head: &LifecycleIntentHead,
        ordinal: u64,
        max_intent_bytes: usize,
    ) -> Result<LifecycleIntentRowLoan>;
}

#[derive(Clone, Default)]
pub struct LifecycleIntentSource(pub Option<Arc<dyn LifecycleIntentRows>>);

impl fmt::Debug for LifecycleIntentSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LifecycleIntentSource")
            .field("installed", &self.0.is_some())
            .finish()
    }
}

impl crate::LifecycleControlState {
    /// The initial deployed cohort may have a bounded legacy map. Newly selected
    /// rows and that map must never claim the same permanent command identity.
    pub fn intent(&self, id: Uuid) -> Result<Option<LifecycleIntentLoan<'_>>> {
        let historical = match &self.intent_head {
            Some(head) if head.count > 0 => self
                .intent_storage()?
                .point(head, id, self.installation.max_state_bytes)?
                .map(LifecycleIntentLoan::Selected),
            _ => None,
        };
        let legacy = self.intents.get(&id);
        if historical.is_some() && legacy.is_some() {
            return Err(Error::from_physical_source(anyhow::anyhow!(
                "duplicate lifecycle intent across retained generations"
            )));
        }
        Ok(historical.or_else(|| legacy.map(LifecycleIntentLoan::Legacy)))
    }

    pub fn intent_storage(&self) -> Result<&dyn LifecycleIntentRows> {
        self.intent_source.0.as_deref().ok_or_else(|| {
            Error::from_physical_source(anyhow::anyhow!(
                "selected lifecycle intent storage is unavailable"
            ))
        })
    }
}

impl crate::TenantState {
    pub fn lifecycle_intent(&self, id: Uuid) -> Result<Option<LifecycleIntentLoan<'_>>> {
        self.lifecycle_control
            .as_ref()
            .map(|control| control.intent(id))
            .transpose()
            .map(Option::flatten)
    }
}
