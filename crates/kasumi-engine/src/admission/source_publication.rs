//! Two native publication lanes owned by the installed MemoryCore. There is no
//! SourceRoots activation, census reservation, or canonical scratch allowance.
use super::{
    ALLOCATION_ALLOWANCE, ChargeKind, ChargeOrigin, MemoryCore, Reservation, ReserveKindError,
};
use kasumi_kv::{
    SourceAccountBackend, SourceAccountInstall, SourceAccountRetirement, SourceBankSnapshot,
    SourceChildInstall, SourceFundingPurpose, SourceFundingRequests, SourceHistoryBackend,
    SourceHistoryCommit, SourceHistoryInstall, SourceMemoryProvider, SourcePoolBackend,
    SourcePoolInstall,
};
use std::{
    io,
    mem::{size_of, swap},
    sync::{Arc, Mutex},
};

fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| io::ErrorKind::OutOfMemory.into())
}
fn allocation<T>() -> io::Result<u64> {
    add(size_of::<T>() as u64, ALLOCATION_ALLOWANCE)
}
fn arc<T>() -> io::Result<u64> {
    add(allocation::<T>()?, 2 * size_of::<usize>() as u64)
}
fn protocol(_: kasumi_kv::SourceFundingCallError) -> io::Error {
    io::ErrorKind::InvalidInput.into()
}
fn poisoned<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::ErrorKind::Other.into()
}
fn reserve(core: &Arc<MemoryCore>, bytes: u64) -> io::Result<Reservation> {
    core.reserve_kind_raw(
        bytes,
        None,
        ChargeKind::Resident,
        ChargeOrigin::DocumentSource,
    )
    .map_err(|error| match error {
        ReserveKindError::Exhausted => io::ErrorKind::OutOfMemory.into(),
        ReserveKindError::IdentifierExhausted | ReserveKindError::Missing => {
            io::ErrorKind::Other.into()
        }
    })
}
#[derive(Clone, Copy)]
struct Quote {
    fixed: u64,
    lane: u64,
    history: u64,
    total: u64,
}
impl Quote {
    fn for_requests(requests: SourceFundingRequests) -> io::Result<Self> {
        let fixed = add(
            add(
                add(
                    arc::<Bank>()?,
                    kasumi_kv::source_backend_allocation_bytes::<Pool>()?,
                )?,
                requests.controller_bytes()?,
            )?,
            add(
                requests.wrapped_bytes(SourceFundingPurpose::Rights),
                kasumi_kv::ResidentAllocation::token_allocation_bytes::<BankFixedCredit>()?,
            )?,
        )?;
        let lane = add(
            add(
                arc::<Account>()?,
                kasumi_kv::source_backend_allocation_bytes::<AccountFacade>()?,
            )?,
            add(
                add(
                    requests.wrapped_bytes(SourceFundingPurpose::Backing),
                    kasumi_kv::ResidentAllocation::token_allocation_bytes::<SourceChildCredit>()?,
                )?,
                add(
                    requests.wrapped_bytes(SourceFundingPurpose::Pin),
                    kasumi_kv::ResidentAllocation::token_allocation_bytes::<SourceChildCredit>()?,
                )?,
            )?,
        )?;
        let history = add(
            lane,
            kasumi_kv::source_backend_allocation_bytes::<History>()?,
        )?;
        Ok(Self {
            fixed,
            lane,
            history,
            total: add(
                fixed,
                lane.checked_mul(2).ok_or(io::ErrorKind::OutOfMemory)?,
            )?,
        })
    }
}

// Every alias elects the final payload through into_inner. There is no Weak.
macro_rules! owner {
    ($name:ident, $body:ident) => {
        struct $name(Option<Arc<$body>>);
        impl $name {
            fn get(&self) -> &$body {
                self.0.as_deref().expect("live source owner")
            }
        }
        impl Clone for $name {
            fn clone(&self) -> Self {
                Self(Some(self.0.as_ref().unwrap().clone()))
            }
        }
        impl Drop for $name {
            fn drop(&mut self) {
                if let Some(value) = self.0.take() {
                    drop(Arc::into_inner(value));
                }
            }
        }
    };
}
owner!(BankRef, Bank);
owner!(AccountRef, Account);
#[derive(Clone, Copy, PartialEq, Eq)]
enum BankPhase {
    Open,
    Sealing,
    Sealed,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Assignment {
    Free,
    Assigned,
    Retained,
}
#[derive(Clone, Copy)]
struct Lane {
    ticket: u64,
    retired_through: u64,
    assignment: Assignment,
}
struct BankState {
    phase: BankPhase,
    lanes: [Lane; 2],
    serial: u64,
    rights_issued: bool,
    grant: Option<Reservation>,
    charged: u64,
}
struct Bank {
    core: Arc<MemoryCore>,
    quote: Quote,
    state: Mutex<BankState>,
}
struct Pool {
    bank: BankRef,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum AccountPhase {
    Active,
    Frozen,
    Retiring,
    Retained,
}
enum Origin {
    Publication,
    History(Reservation),
}
struct AccountState {
    phase: AccountPhase,
    issued: [bool; 2],
    live: [bool; 2],
    origin: Origin,
}
struct Account {
    bank: BankRef,
    lane: usize,
    ticket: u64,
    state: Mutex<AccountState>,
}
struct AccountFacade {
    account: AccountRef,
}
struct SourceChildCredit {
    account: AccountRef,
    purpose: usize,
    ticket: u64,
}
struct BankFixedCredit {
    _bank: BankRef,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum HistoryPhase {
    Prepared,
    Committing,
    Committed,
}
struct History {
    account: AccountRef,
    replacement: Origin,
    phase: HistoryPhase,
}

impl SourceMemoryProvider for MemoryCore {
    fn install_source_pool(self: Arc<Self>, install: &mut SourcePoolInstall<'_>) -> io::Result<()> {
        let provider: Arc<dyn SourceMemoryProvider> = self.clone();
        let permit = install.try_begin_bind(provider).map_err(protocol)?;
        let quote = Quote::for_requests(permit.requests())?;
        // This exact origin bypasses audit TLS and preserves mandatory headroom.
        let grant = reserve(&self, quote.total)?;
        // No provider/user callbacks or fallible work after the actual grant.
        let bank = BankRef(Some(Arc::new(Bank {
            core: self,
            quote,
            state: Mutex::new(BankState {
                phase: BankPhase::Open,
                lanes: [Lane {
                    ticket: 0,
                    retired_through: 0,
                    assignment: Assignment::Free,
                }; 2],
                serial: 0,
                rights_issued: false,
                grant: Some(grant),
                charged: quote.total,
            }),
        })));
        #[cfg(test)]
        allocation_tests::bank(&bank);
        permit.bind(Pool { bank });
        Ok(())
    }
}
impl Pool {
    fn provider(&self) -> Arc<dyn SourceMemoryProvider> {
        self.bank.get().core.clone()
    }
}
impl SourcePoolBackend for Pool {
    fn install_account(&self, install: &mut SourceAccountInstall<'_>) -> io::Result<()> {
        let permit = install.try_begin_bind(self.provider()).map_err(protocol)?;
        let mut state = self.bank.get().state.lock().map_err(poisoned)?;
        if state.phase != BankPhase::Open {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let lane = state
            .lanes
            .iter()
            .position(|lane| lane.assignment == Assignment::Free)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        let ticket = state.serial.checked_add(1).ok_or(io::ErrorKind::Other)?;
        state.serial = ticket;
        state.lanes[lane].ticket = ticket;
        state.lanes[lane].assignment = Assignment::Assigned;
        drop(state);
        let account = AccountRef(Some(Arc::new(Account {
            bank: self.bank.clone(),
            lane,
            ticket,
            state: Mutex::new(AccountState {
                phase: AccountPhase::Active,
                issued: [false; 2],
                live: [false; 2],
                origin: Origin::Publication,
            }),
        })));
        #[cfg(test)]
        allocation_tests::account(&account);
        permit.bind(AccountFacade { account }, lane, ticket);
        Ok(())
    }
    fn acquire_rights(&self, install: &mut SourceChildInstall<'_>) -> io::Result<()> {
        if install.purpose() != SourceFundingPurpose::Rights {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let permit = install.try_begin_bind(self.provider()).map_err(protocol)?;
        let mut state = self.bank.get().state.lock().map_err(poisoned)?;
        if state.phase != BankPhase::Open || state.rights_issued {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        state.rights_issued = true;
        drop(state);
        permit.bind(BankFixedCredit {
            _bank: self.bank.clone(),
        });
        Ok(())
    }
    fn begin_seal(&self) -> io::Result<()> {
        let mut state = self.bank.get().state.lock().map_err(poisoned)?;
        if state.phase == BankPhase::Open {
            state.phase = BankPhase::Sealing;
        }
        Ok(())
    }
    fn seal(&self) -> io::Result<()> {
        let mut state = self.bank.get().state.lock().map_err(poisoned)?;
        if state.phase == BankPhase::Sealed {
            return Ok(());
        }
        // One-way barrier precedes unlocking; new checkout cannot race shrink.
        state.phase = BankPhase::Sealing;
        if state
            .lanes
            .iter()
            .any(|lane| lane.assignment != Assignment::Free)
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let grant = state.grant.take().ok_or(io::ErrorKind::Other)?;
        drop(state);
        let mut guard = ShrinkGuard {
            bank: self.bank.clone(),
            grant: Some(grant),
        };
        guard
            .grant
            .as_mut()
            .unwrap()
            .retain(self.bank.get().quote.fixed);
        let mut state = self.bank.get().state.lock().map_err(poisoned)?;
        state.grant = guard.grant.take();
        state.charged = self.bank.get().quote.fixed;
        state.phase = BankPhase::Sealed;
        Ok(())
    }
    fn retirement(&self, stamp: SourceAccountRetirement) -> bool {
        self.bank
            .get()
            .state
            .lock()
            .ok()
            .and_then(|state| {
                state
                    .lanes
                    .get(stamp.lane())
                    .map(|lane| stamp.ticket() != 0 && lane.retired_through >= stamp.ticket())
            })
            .unwrap_or(false)
    }
    fn snapshot(&self) -> SourceBankSnapshot {
        #[cfg(test)]
        allocation_tests::pool_box(self);
        let state = self
            .bank
            .get()
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        SourceBankSnapshot {
            fixed_bytes: self.bank.get().quote.fixed,
            lane_bytes: self.bank.get().quote.lane,
            charged_bytes: state.charged,
            assigned: state
                .lanes
                .iter()
                .filter(|lane| lane.assignment == Assignment::Assigned)
                .count(),
            retained: state
                .lanes
                .iter()
                .filter(|lane| lane.assignment == Assignment::Retained)
                .count(),
            sealed: state.phase == BankPhase::Sealed,
        }
    }
}
struct ShrinkGuard {
    bank: BankRef,
    grant: Option<Reservation>,
}
impl Drop for ShrinkGuard {
    fn drop(&mut self) {
        if let Some(grant) = self.grant.take() {
            // Restore actual custody even if retain/lock unwinds. No callback.
            self.bank
                .get()
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .grant = Some(grant);
        }
    }
}
impl SourceAccountBackend for AccountFacade {
    fn allow_retirement(&self) -> io::Result<()> {
        let mut state = self.account.get().state.lock().map_err(poisoned)?;
        if state.live.iter().any(|live| *live) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if state.phase == AccountPhase::Retained {
            return Err(io::ErrorKind::Other.into());
        }
        state.phase = AccountPhase::Retiring;
        Ok(())
    }
    fn acquire(&self, install: &mut SourceChildInstall<'_>) -> io::Result<()> {
        #[cfg(test)]
        allocation_tests::account_box(self);
        let purpose = match install.purpose() {
            SourceFundingPurpose::Backing => 0,
            SourceFundingPurpose::Pin => 1,
            SourceFundingPurpose::Rights => return Err(io::ErrorKind::InvalidInput.into()),
        };
        let provider: Arc<dyn SourceMemoryProvider> = self.account.get().bank.get().core.clone();
        let permit = install.try_begin_bind(provider).map_err(protocol)?;
        let mut state = self.account.get().state.lock().map_err(poisoned)?;
        if state.phase != AccountPhase::Active || state.issued[purpose] {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        state.issued[purpose] = true;
        state.live[purpose] = true;
        drop(state);
        permit.bind(SourceChildCredit {
            account: self.account.clone(),
            purpose,
            ticket: self.account.get().ticket,
        });
        Ok(())
    }
    fn install_history(&self, install: &mut SourceHistoryInstall<'_>) -> io::Result<()> {
        let provider: Arc<dyn SourceMemoryProvider> = self.account.get().bank.get().core.clone();
        let permit = install.try_begin_bind(provider).map_err(protocol)?;
        {
            let state = self.account.get().state.lock().map_err(poisoned)?;
            if state.phase != AccountPhase::Active
                || state.issued != [true; 2]
                || state.live != [true; 2]
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        }
        let ordinary = match self.account.get().bank.get().core.reserve_kind_raw(
            self.account.get().bank.get().quote.history,
            None,
            ChargeKind::Resident,
            ChargeOrigin::DocumentSource,
        ) {
            Ok(grant) => grant,
            Err(ReserveKindError::Exhausted) => {
                return Err(permit.refuse_capacity(io::ErrorKind::OutOfMemory.into()));
            }
            Err(ReserveKindError::IdentifierExhausted | ReserveKindError::Missing) => {
                return Err(io::ErrorKind::Other.into());
            }
        };
        #[cfg(test)]
        super::installed_drop_probe::observe(&ordinary);
        permit.bind(History {
            account: self.account.clone(),
            replacement: Origin::History(ordinary),
            phase: HistoryPhase::Prepared,
        });
        Ok(())
    }
}
impl SourceHistoryBackend for History {
    fn commit(&mut self, native: &mut SourceHistoryCommit<'_>) -> io::Result<()> {
        if self.phase != HistoryPhase::Prepared {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.phase = HistoryPhase::Committing;
        let account = self.account.get();
        let bank = account.bank.get();
        let mut bank_state = bank.state.lock().map_err(poisoned)?;
        let mut state = account.state.lock().map_err(poisoned)?;
        let lane = bank_state
            .lanes
            .get_mut(account.lane)
            .ok_or(io::ErrorKind::Other)?;
        if lane.ticket != account.ticket
            || lane.assignment != Assignment::Assigned
            || state.phase != AccountPhase::Active
            || !matches!(state.origin, Origin::Publication)
        {
            return Err(io::ErrorKind::Other.into());
        }
        if !matches!(self.replacement, Origin::History(_)) {
            return Err(io::ErrorKind::Other.into());
        }
        state.phase = AccountPhase::Frozen;
        // The preowned replacement is a field outside the destructive Attempt:
        // even an unexpected unwind after native effect retains both grants.
        if !native.commit() {
            state.phase = AccountPhase::Retained;
            return Err(io::ErrorKind::Other.into());
        }
        // Infallible suffix: fields/references/replacement already validated.
        swap(&mut state.origin, &mut self.replacement);
        lane.assignment = Assignment::Free;
        lane.retired_through = account.ticket;
        self.phase = HistoryPhase::Committed;
        drop(state);
        drop(bank_state);
        Ok(())
    }
}
impl Drop for SourceChildCredit {
    fn drop(&mut self) {
        let mut state = self.account.get().state.lock().unwrap_or_else(|p| {
            let mut state = p.into_inner();
            state.phase = AccountPhase::Retained;
            state
        });
        if self.ticket != self.account.get().ticket || !state.live[self.purpose] {
            state.phase = AccountPhase::Retained;
        } else {
            state.live[self.purpose] = false;
        }
    }
}
impl Drop for Account {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(|p| p.into_inner());
        // History already transferred the logical assignment. Its real grant
        // remains in this payload until the actual Account Arc shell is gone.
        if let Origin::History(charge) = &state.origin {
            let _ = charge;
            return;
        }
        let mut bank = self
            .bank
            .get()
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let lane = &mut bank.lanes[self.lane];
        if lane.ticket != self.ticket || lane.assignment != Assignment::Assigned {
            lane.assignment = Assignment::Retained;
            return;
        }
        if state.phase == AccountPhase::Retiring && state.live == [false; 2] {
            lane.assignment = Assignment::Free;
            lane.retired_through = self.ticket;
        } else {
            lane.assignment = Assignment::Retained;
        }
    }
}

#[cfg(test)]
#[path = "source_publication_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "source_publication_allocation_tests.rs"]
pub(crate) mod allocation_tests;

#[cfg(test)]
#[path = "registered_source_funding_tests.rs"]
mod registered_tests;

#[cfg(test)]
#[path = "protected_source_points_tests.rs"]
mod protected_point_tests;
