//! Replica-local application input custody. This funds one actual input buffer
//! and its fixed controls plus an optional exact mutation change-tree recipe.
//! The recipe covers only target Strings and pinned BTree nodes, not Command
//! decoding, document reduction, candidate, selection,
//! index, response, snapshot restore, transport decoding or Entry DTO allocation.
//! Its loan is deliberately not a Native capacity or application-completion
//! certificate. This first cut transfers only the ordinary leader's original
//! proposal grant before submission. Ordinary persisted replay uses its named
//! point-read producer's same original plaintext/control lease. Follower transport
//! remains explicitly unsupported; EntryVec and semantic producers stay OPEN.

use kasumi_store::{DiskMemoryLease, NodeDiskMemoryAdmission};

#[path = "mutation_change_tree.rs"]
mod mutation_change_tree;
use mutation_change_tree::{MutationChangeTreeRecipe, MutationChangeTreeState};
use sha2::{Digest, Sha256};
use std::{
    alloc::Layout,
    io,
    sync::{Arc, OnceLock},
};

fn add(left: u64, right: u64) -> io::Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| io::ErrorKind::InvalidInput.into())
}
fn allocation(layout: Layout) -> io::Result<u64> {
    if layout.size() == 0 {
        return Ok(0);
    }
    u64::try_from(
        layout
            .size()
            .checked_next_power_of_two()
            .and_then(|bytes| bytes.checked_add(64))
            .ok_or(io::ErrorKind::InvalidInput)?,
    )
    .map_err(|_| io::ErrorKind::InvalidInput.into())
}

/// The exact fixed control layout plus the actual owned input capacity. This is
/// a pure quote, not authority supplied as public extra bytes.
#[derive(Clone, Copy)]
pub struct ApplicationInputRequirements {
    body_capacity: usize,
    mutation_change_tree: Option<MutationChangeTreeRecipe>,
}
impl ApplicationInputRequirements {
    /// Prospective quote for a producer that will allocate exactly this Vec
    /// capacity. This supplies no grant and certifies no other producer output.
    pub fn for_capacity(body_capacity: usize) -> Self {
        Self {
            body_capacity,
            mutation_change_tree: None,
        }
    }
    /// Pure quote for the existing batch_changes producer: every input target
    /// allocates both Strings, including duplicate targets that are then freed.
    /// This cannot quote an arbitrary extra byte allowance or another producer.
    pub fn with_mutation_change_tree(
        mut self,
        batch: &kasumi_types::MutationBatch,
    ) -> io::Result<Self> {
        self.mutation_change_tree = Some(MutationChangeTreeRecipe::prepare(batch)?);
        Ok(self)
    }
    pub fn mutation_change_tree_bytes(&self) -> Option<u64> {
        self.mutation_change_tree
            .map(|recipe| recipe.request_bytes())
    }
    pub fn control_bytes() -> io::Result<u64> {
        // Same actual sized Arc representation; use the shared pure control
        // model without creating a second charge or opaque adapter.
        kasumi_types::SharedBudgetCharge::required_bytes::<InputState>()
    }
    pub fn request_bytes(&self) -> io::Result<u64> {
        add(
            add(
                Self::control_bytes()?,
                allocation(
                    Layout::array::<u8>(self.body_capacity)
                        .map_err(|_| io::ErrorKind::InvalidInput)?,
                )?,
            )?,
            self.mutation_change_tree_bytes().unwrap_or(0),
        )
    }
    /// A concrete existing grant is converted only after admitting its actual
    /// token Box. The receiver does not reserve again or grow accepted credit.
    pub fn with_token<T: Send + Sync + 'static>(&self) -> io::Result<u64> {
        add(
            self.request_bytes()?,
            DiskMemoryLease::token_allocation_bytes::<T>()?,
        )
    }
}

/// Before admission this keeps the original input on the caller's existing
/// work owner. No control/token allocation occurs in this constructor.
pub struct ApplicationInputInstall {
    bytes: Option<Vec<u8>>,
    memory: Arc<dyn NodeDiskMemoryAdmission>,
    requirements: ApplicationInputRequirements,
    installed: Option<AdmittedApplicationInput>,
}
impl ApplicationInputInstall {
    pub fn new(bytes: Vec<u8>, memory: Arc<dyn NodeDiskMemoryAdmission>) -> Self {
        let requirements = ApplicationInputRequirements::for_capacity(bytes.capacity());
        Self {
            bytes: Some(bytes),
            memory,
            requirements,
            installed: None,
        }
    }
    /// Prepare the one concrete recipe before bind allocates its token/control.
    /// The receiver still owns the unchanged pending input on every refusal.
    pub fn prepare_mutation_change_tree(
        &mut self,
        batch: &kasumi_types::MutationBatch,
    ) -> Result<(), InputBindingError> {
        if self.bytes.is_none()
            || self.installed.is_some()
            || self.requirements.mutation_change_tree.is_some()
        {
            return Err(InputBindingError::Repeated);
        }
        self.requirements = self
            .requirements
            .with_mutation_change_tree(batch)
            .map_err(|_| InputBindingError::Insufficient)?;
        Ok(())
    }
    pub fn requirements(&self) -> ApplicationInputRequirements {
        self.requirements
    }
    /// Borrow the unchanged original before installation; this conveys no
    /// extraction, mutation, grant or admission authority.
    pub fn pending_bytes(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }
    pub fn try_bind<'a>(
        &'a mut self,
        memory: &Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<ApplicationInputPermit<'a>, InputBindingError> {
        if !Arc::ptr_eq(&self.memory, memory) {
            return Err(InputBindingError::Foreign);
        }
        if self.bytes.is_none() || self.installed.is_some() {
            return Err(InputBindingError::Repeated);
        }
        Ok(ApplicationInputPermit { install: self })
    }
    fn install(&mut self, charge: DiskMemoryLease) {
        let bytes = self.bytes.take().expect("one original input buffer");
        let digest = Sha256::digest(&bytes).into();
        self.installed = Some(AdmittedApplicationInput(InputOwner::Leader(Some(
            Arc::new(InputState {
                bytes,
                digest,
                binding: OnceLock::new(),
                memory: self.memory.clone(),
                mutation_change_tree: self
                    .requirements
                    .mutation_change_tree
                    .map(MutationChangeTreeState::new),
                _charge: charge,
            }),
        ))));
    }
    #[allow(
        clippy::result_large_err,
        reason = "refusal retains the whole pending input and inline recipe without allocating an error Box"
    )]
    pub fn finish(mut self) -> Result<AdmittedApplicationInput, Self> {
        match self.installed.take() {
            Some(original) => Ok(original),
            None => Err(self),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputBindingError {
    Foreign,
    Repeated,
    Missing,
    Insufficient,
}
/// Trusted concrete provider boundary. Only a grant whose exact request and
/// token quote were admitted may be bound. Supported production use is the
/// original MemoryCore Reservation checked against its authoritative ledger.
/// This contract does not assert funding of an arbitrary nested token payload.
pub struct ApplicationInputPermit<'a> {
    install: &'a mut ApplicationInputInstall,
}
impl ApplicationInputPermit<'_> {
    pub fn requirements(&self) -> ApplicationInputRequirements {
        self.install.requirements
    }
    pub fn bind<T: Send + Sync + 'static>(self, original: T) {
        self.install.install(DiskMemoryLease::new(original));
    }
}

struct InputState {
    bytes: Vec<u8>,
    digest: [u8; 32],
    binding: OnceLock<openraft::LogId<u64>>,
    memory: Arc<dyn NodeDiskMemoryAdmission>,
    mutation_change_tree: Option<MutationChangeTreeState>,
    // Last: input backing and all its own control allocations precede refund.
    _charge: DiskMemoryLease,
}
enum InputOwner {
    Leader(Option<Arc<InputState>>),
    Replay(crate::replay_input::ReplayInput),
}
/// Every strong alias is closed. Leader input retains its original paid input
/// control; replay retains its original paid immutable point control. Final
/// control deallocation precedes original bytes/token/refund. No Weak/raw Arc,
/// payload extraction, refill or public retirement predicate exists.
pub struct AdmittedApplicationInput(InputOwner);
impl AdmittedApplicationInput {
    pub(crate) fn from_replay(input: crate::replay_input::ReplayInput) -> Self {
        Self(InputOwner::Replay(input))
    }
    /// Claim only a leader's known recipe. Replay's original point fee pays
    /// input backing only: None supplies no mutation-tree allowance, cannot be
    /// converted to a grant and does not certify its existing semantic producer.
    pub fn claim_mutation_change_tree(
        &self,
        log_id: openraft::LogId<u64>,
        batch: &kasumi_types::MutationBatch,
    ) -> Result<Option<MutationChangeTreeRetention>, InputBindingError> {
        match &self.0 {
            InputOwner::Leader(state) => {
                let state = state.as_deref().expect("live application input");
                if state.binding.get() != Some(&log_id) {
                    return Err(InputBindingError::Foreign);
                }
                let producer = state
                    .mutation_change_tree
                    .as_ref()
                    .ok_or(InputBindingError::Missing)?;
                producer.claim(batch)?;
                Ok(Some(MutationChangeTreeRetention {
                    _original: self.clone(),
                }))
            }
            InputOwner::Replay(input) => {
                input.require_log_id(log_id)?;
                Ok(None)
            }
        }
    }
    /// Fixture-only binding uses the actual original owner without implying
    /// that its synthetic LogId proves consensus, publication or native capacity.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn bind_fixture_log_id(
        &self,
        log_id: openraft::LogId<u64>,
    ) -> Result<(), InputBindingError> {
        self.bind(log_id)
    }
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            InputOwner::Leader(state) => &state.as_deref().expect("live application input").bytes,
            InputOwner::Replay(input) => input.as_bytes(),
        }
    }
    fn digest(&self) -> [u8; 32] {
        match &self.0 {
            InputOwner::Leader(state) => state.as_deref().expect("live application input").digest,
            InputOwner::Replay(input) => input.digest(),
        }
    }
    pub(crate) fn bind(&self, log_id: openraft::LogId<u64>) -> Result<(), InputBindingError> {
        match &self.0 {
            InputOwner::Leader(state) => {
                let binding = state
                    .as_deref()
                    .expect("live application input")
                    .binding
                    .get_or_init(|| log_id);
                if *binding == log_id {
                    Ok(())
                } else {
                    Err(InputBindingError::Foreign)
                }
            }
            InputOwner::Replay(input) => input.require_log_id(log_id),
        }
    }
    pub(crate) fn require_memory(
        &self,
        memory: &Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<(), InputBindingError> {
        let matches = match &self.0 {
            InputOwner::Leader(state) => Arc::ptr_eq(
                &state.as_deref().expect("live application input").memory,
                memory,
            ),
            InputOwner::Replay(input) => input.is_from_memory(memory),
        };
        if matches {
            Ok(())
        } else {
            Err(InputBindingError::Foreign)
        }
    }
    pub(crate) fn loan(
        &self,
        log_id: openraft::LogId<u64>,
    ) -> Result<ApplicationInputLoan, InputBindingError> {
        match &self.0 {
            InputOwner::Leader(state)
                if state
                    .as_deref()
                    .expect("live application input")
                    .binding
                    .get()
                    != Some(&log_id) =>
            {
                return Err(InputBindingError::Foreign);
            }
            InputOwner::Replay(input) => input.require_log_id(log_id)?,
            InputOwner::Leader(_) => {}
        }
        Ok(ApplicationInputLoan {
            original: self.clone(),
            log_id,
        })
    }
}
impl Clone for AdmittedApplicationInput {
    fn clone(&self) -> Self {
        Self(match &self.0 {
            InputOwner::Leader(original) => InputOwner::Leader(original.clone()),
            InputOwner::Replay(original) => InputOwner::Replay(original.clone()),
        })
    }
}
impl Drop for AdmittedApplicationInput {
    fn drop(&mut self) {
        if let InputOwner::Leader(original) = &mut self.0 {
            drop(Arc::into_inner(
                original.take().expect("live application input"),
            ));
        }
        // Replay's closed point owner drops inline, freeing its original paid
        // control before original record/token; existing storage custody follows.
    }
}
/// Move-only retention of the exact original input/budget control. There is no
/// raw handle, mutable payload, refill, clone or independent grant. The Engine
/// stores this before the concrete tree construction on its actual ApplyOwner;
/// accepted delta backing dies before that owner's final same-grant aliases.
pub struct MutationChangeTreeRetention {
    _original: AdmittedApplicationInput,
}

/// A move-only input-retention loan. It certifies only the same encoded input
/// backing through a synchronous apply; it cannot pay independent allocations.
pub struct ApplicationInputLoan {
    original: AdmittedApplicationInput,
    log_id: openraft::LogId<u64>,
}
impl ApplicationInputLoan {
    pub fn require_bytes(
        &self,
        log_id: openraft::LogId<u64>,
        bytes: &[u8],
    ) -> Result<(), InputBindingError> {
        if self.log_id == log_id
            && self.original.as_bytes() == bytes
            && <[u8; 32]>::from(Sha256::digest(bytes)) == self.original.digest()
        {
            Ok(())
        } else {
            Err(InputBindingError::Foreign)
        }
    }
    pub fn require_memory(
        &self,
        memory: &Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<(), InputBindingError> {
        self.original.require_memory(memory)
    }
    pub fn retained_input(&self) -> AdmittedApplicationInput {
        self.original.clone()
    }
}

#[cfg(test)]
#[path = "accepted_input_tests.rs"]
mod tests;
