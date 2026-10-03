//! Fixed metadata bank. Census keeps BankRef-only holds/witnesses; it never
//! keeps the AccountRef whose final allocation it is waiting to observe.
use super::*;

macro_rules! owner {
    ($name:ident, $body:ident) => {
        struct $name(Option<Arc<$body>>);
        impl $name {
            fn get(&self) -> &$body {
                self.0.as_deref().expect("retained metadata owner")
            }
        }
        impl Clone for $name {
            fn clone(&self) -> Self {
                Self(Some(self.0.as_ref().unwrap().clone()))
            }
        }
        impl Drop for $name {
            fn drop(&mut self) {
                if let Some(owner) = self.0.take() {
                    drop(Arc::into_inner(owner));
                }
            }
        }
    };
}
owner!(BankRef, Bank);
owner!(AccountRef, Account);

impl BankRef {
    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(self.0.as_ref().unwrap(), other.0.as_ref().unwrap())
    }
}

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
    retired: u64,
    assignment: Assignment,
}
struct BankState {
    phase: BankPhase,
    serial: u64,
    lanes: [Lane; 2],
    standing: [Option<DiskMemoryLease>; 2],
}
struct Bank {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    pool: StorageOwnerId,
    quote: Quote,
    fenced: AtomicBool,
    state: Mutex<BankState>,
    // BankRef retires this actual Arc shell before any of these credits drop.
    _fixed: DiskMemoryLease,
}
#[derive(Clone, Copy)]
struct Quote {
    fixed: u64,
    lane: u64,
    report: u64,
    payload: u64,
}
impl Quote {
    fn new() -> io::Result<Self> {
        let [report, payload] = crate::RegisteredNodeRead::memory_requests()?;
        let token = DiskMemoryLease::token_allocation_bytes::<ChildCredit>()?;
        let lane = disk_memory::add(
            disk_memory::arc::<Account>()?,
            disk_memory::add(
                disk_memory::add(report, token)?,
                disk_memory::add(payload, token)?,
            )?,
        )?;
        Ok(Self {
            fixed: disk_memory::arc::<Bank>()?,
            lane,
            report,
            payload,
        })
    }
}

pub(crate) struct StoreSourceMetadataBank {
    bank: BankRef,
}
impl StoreSourceMetadataBank {
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn allocation_address(&self) -> usize {
        std::ptr::from_ref(self.bank.get()) as usize
    }

    pub(crate) fn requests() -> io::Result<[u64; 3]> {
        let quote = Quote::new()?;
        Ok([quote.fixed, quote.lane, quote.lane])
    }
    // Preparations are real retained caller fields, acquired independently
    // before allocating the bank. No provider continuation runs after taking.
    pub(crate) fn install(
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        pool: StorageOwnerId,
        preparations: &mut [MetadataPreparation; 3],
    ) -> io::Result<Option<Self>> {
        let quote = Quote::new()?;
        if !preparations[0].ready_for(provider, SourceMetadataPurpose::Fixed, quote.fixed)
            || !preparations[1].ready_for(
                provider,
                SourceMetadataPurpose::PublicationLane,
                quote.lane,
            )
            || !preparations[2].ready_for(
                provider,
                SourceMetadataPurpose::PublicationLane,
                quote.lane,
            )
        {
            return Ok(None);
        }
        let fixed = preparations[0]
            .take_for(provider, SourceMetadataPurpose::Fixed, quote.fixed)
            .ok_or_else(invalid)?;
        let first = preparations[1]
            .take_for(provider, SourceMetadataPurpose::PublicationLane, quote.lane)
            .ok_or_else(invalid)?;
        let second = preparations[2]
            .take_for(provider, SourceMetadataPurpose::PublicationLane, quote.lane)
            .ok_or_else(invalid)?;
        Ok(Some(Self {
            bank: BankRef(Some(Arc::new(Bank {
                provider: provider.clone(),
                pool,
                quote,
                fenced: AtomicBool::new(false),
                state: Mutex::new(BankState {
                    phase: BankPhase::Open,
                    serial: 0,
                    lanes: [Lane {
                        ticket: 0,
                        retired: 0,
                        assignment: Assignment::Free,
                    }; 2],
                    standing: [Some(first), Some(second)],
                }),
                _fixed: fixed,
            }))),
        }))
    }
    pub(crate) fn hold(&self) -> SourceMetadataBankHold {
        SourceMetadataBankHold {
            bank: self.bank.clone(),
        }
    }
    pub(crate) fn checkout(&self, lane_index: usize) -> io::Result<SourceMetadataAccount> {
        let bank = self.bank.get();
        if bank.fenced.load(Ordering::Acquire) {
            return Err(io::ErrorKind::Other.into());
        }
        let mut state = bank.state.lock().map_err(poisoned)?;
        if state.phase != BankPhase::Open
            || lane_index >= 2
            || state.lanes[lane_index].assignment != Assignment::Free
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let ticket = state.serial.checked_add(1).ok_or(io::ErrorKind::Other)?;
        state.serial = ticket;
        state.lanes[lane_index] = Lane {
            ticket,
            retired: state.lanes[lane_index].retired,
            assignment: Assignment::Assigned,
        };
        // This is the only account allocation; its actual Arc/body was funded
        // in the standing lane before checkout. No external code runs here.
        drop(state);
        Ok(SourceMetadataAccount {
            account: Some(AccountRef(Some(Arc::new(Account {
                bank: self.bank.clone(),
                lane: lane_index,
                ticket,
                state: Mutex::new(AccountState {
                    phase: AccountPhase::Active,
                    issued: [false; 2],
                    live: [false; 2],
                    origin: Origin::Publication,
                }),
            })))),
        })
    }
    pub(crate) fn begin_seal(&self) -> io::Result<()> {
        let mut state = self.bank.get().state.lock().map_err(poisoned)?;
        if state.phase == BankPhase::Open {
            state.phase = BankPhase::Sealing;
        }
        Ok(())
    }
    // All assignments must have positively retired/transferred. Move the real
    // standing tokens to the retained caller BEFORE destroying any token;
    // their cleanup is observed outside this mutex and all census locks.
    pub(crate) fn take_sealed_lanes(
        &self,
        target: &mut [Option<DiskMemoryLease>; 2],
    ) -> io::Result<bool> {
        let bank = self.bank.get();
        let mut state = bank.state.lock().map_err(poisoned)?;
        if bank.fenced.load(Ordering::Acquire) || state.phase == BankPhase::Open {
            return Err(invalid());
        }
        if state
            .lanes
            .iter()
            .any(|lane| lane.assignment != Assignment::Free)
        {
            return Ok(false);
        }
        if state.phase == BankPhase::Sealed {
            return Ok(true);
        }
        if target.iter().any(Option::is_some) {
            return Err(invalid());
        }
        for (target, standing) in target.iter_mut().zip(&mut state.standing) {
            *target = standing.take();
        }
        state.phase = BankPhase::Sealed;
        Ok(true)
    }
}

#[derive(Clone)]
pub(crate) struct SourceMetadataBankHold {
    bank: BankRef,
}
impl SourceMetadataBankHold {
    pub(crate) fn belongs_to_pool(&self, pool: StorageOwnerId) -> bool {
        self.bank.get().pool == pool
    }
    pub(crate) fn require_provider(
        &self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
    ) -> io::Result<()> {
        if Arc::ptr_eq(&self.bank.get().provider, provider) {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceMetadataRetirement {
    Pending,
    Retired,
    Retained,
}
#[derive(Clone)]
pub(crate) struct SourceMetadataWitness {
    bank: BankRef,
    lane: usize,
    ticket: u64,
}
impl SourceMetadataWitness {
    pub(crate) fn same_bank(&self, hold: &SourceMetadataBankHold) -> bool {
        self.bank.same(&hold.bank)
    }
    pub(crate) fn into_hold(self) -> SourceMetadataBankHold {
        SourceMetadataBankHold { bank: self.bank }
    }
    pub(crate) fn status(&self) -> SourceMetadataRetirement {
        let bank = self.bank.get();
        if bank.fenced.load(Ordering::Acquire) {
            return SourceMetadataRetirement::Retained;
        }
        let state = match bank.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return SourceMetadataRetirement::Pending,
            Err(TryLockError::Poisoned(_)) => {
                bank.fenced.store(true, Ordering::Release);
                return SourceMetadataRetirement::Retained;
            }
        };
        let lane = &state.lanes[self.lane];
        if lane.retired >= self.ticket {
            SourceMetadataRetirement::Retired
        } else if lane.ticket != self.ticket || lane.assignment == Assignment::Retained {
            SourceMetadataRetirement::Retained
        } else {
            SourceMetadataRetirement::Pending
        }
    }
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
    History(DiskMemoryLease),
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
struct ChildCredit {
    account: AccountRef,
    purpose: usize,
}
impl Drop for ChildCredit {
    fn drop(&mut self) {
        let account = self.account.get();
        let mut state = account.state.lock().unwrap_or_else(|p| {
            account.bank.get().fenced.store(true, Ordering::Release);
            p.into_inner()
        });
        if !state.live[self.purpose] {
            state.phase = AccountPhase::Retained;
            account.bank.get().fenced.store(true, Ordering::Release);
        } else {
            state.live[self.purpose] = false;
        }
    }
}
impl Drop for Account {
    fn drop(&mut self) {
        // AccountRef already retired the actual Arc/control block. Both token
        // Boxes must be gone before their final AccountRef can reach this path.
        let state = self.state.get_mut().unwrap_or_else(|p| {
            self.bank.get().fenced.store(true, Ordering::Release);
            p.into_inner()
        });
        if let Origin::History(credit) = &state.origin {
            let _ = credit;
            return;
        }
        let bank = self.bank.get();
        let mut state_bank = bank.state.lock().unwrap_or_else(|p| {
            bank.fenced.store(true, Ordering::Release);
            p.into_inner()
        });
        let lane = &mut state_bank.lanes[self.lane];
        if lane.ticket == self.ticket
            && lane.assignment == Assignment::Assigned
            && state.phase == AccountPhase::Retiring
            && state.live == [false; 2]
        {
            lane.assignment = Assignment::Free;
            lane.retired = self.ticket;
        } else {
            lane.assignment = Assignment::Retained;
            bank.fenced.store(true, Ordering::Release);
        }
    }
}

pub(crate) struct SourceMetadataAccount {
    account: Option<AccountRef>,
}
impl SourceMetadataAccount {
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn allocation_address(&self) -> usize {
        std::ptr::from_ref(self.get()) as usize
    }

    fn get(&self) -> &Account {
        self.account.as_ref().expect("live metadata account").get()
    }
    pub(crate) fn right_index(&self) -> usize {
        self.get().lane
    }
    pub(crate) fn witness(&self) -> SourceMetadataWitness {
        let account = self.get();
        SourceMetadataWitness {
            bank: account.bank.clone(),
            lane: account.lane,
            ticket: account.ticket,
        }
    }
    fn child(&self, purpose: usize) -> io::Result<DiskMemoryLease> {
        let account = self.get();
        let mut state = account.state.lock().map_err(poisoned)?;
        if state.phase != AccountPhase::Active
            || state.issued[purpose]
            || account.bank.get().fenced.load(Ordering::Acquire)
        {
            return Err(invalid());
        }
        state.issued[purpose] = true;
        state.live[purpose] = true;
        drop(state);
        Ok(DiskMemoryLease::new(ChildCredit {
            account: self.account.as_ref().unwrap().clone(),
            purpose,
        }))
    }
    pub(crate) fn report_grant(&self) -> io::Result<SourceReportGrant> {
        Ok(SourceReportGrant {
            lease: self.child(0)?,
            provider: self.get().bank.get().provider.clone(),
            bytes: self.get().bank.get().quote.report,
        })
    }
    pub(crate) fn payload_grant(&self) -> io::Result<SourcePayloadGrant> {
        Ok(SourcePayloadGrant {
            lease: self.child(1)?,
            witness: self.witness(),
            bytes: self.get().bank.get().quote.payload,
        })
    }
    // Native/controller disposal is already positively observed by the reader.
    // This releases only its control alias; report/payload tokens stay charged.
    pub(crate) fn allow_retirement(&self) -> io::Result<()> {
        let mut state = self.get().state.lock().map_err(poisoned)?;
        if state.phase == AccountPhase::Retained {
            return Err(io::ErrorKind::Other.into());
        }
        state.phase = AccountPhase::Retiring;
        Ok(())
    }
    pub(crate) fn history(&self) -> io::Result<SourceMetadataHistory> {
        let account = self.get();
        let state = account.state.lock().map_err(poisoned)?;
        if state.phase != AccountPhase::Active
            || state.issued != [true; 2]
            || state.live != [true; 2]
            || !matches!(state.origin, Origin::Publication)
        {
            return Err(invalid());
        }
        // Ordinary replacement admission is still reversible. The account
        // remains active until the guarded metadata exchange actually applies.
        Ok(SourceMetadataHistory {
            account: self.account.as_ref().unwrap().clone(),
            admission: MetadataPreparation::new(),
            replacement: None,
            phase: HistoryPhase::Queued,
            cleanup: MetadataAttempt::new(),
        })
    }
}

pub(crate) struct SourceReportGrant {
    lease: DiskMemoryLease,
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    bytes: u64,
}
impl SourceReportGrant {
    pub(crate) fn require(
        &self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        bytes: u64,
    ) -> io::Result<()> {
        if bytes == self.bytes && Arc::ptr_eq(provider, &self.provider) {
            Ok(())
        } else {
            Err(invalid())
        }
    }
    pub(crate) fn into_lease(self) -> DiskMemoryLease {
        self.lease
    }
}
pub(crate) struct SourcePayloadGrant {
    lease: DiskMemoryLease,
    witness: SourceMetadataWitness,
    bytes: u64,
}
impl SourcePayloadGrant {
    pub(crate) fn require(
        &self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        bytes: u64,
    ) -> io::Result<()> {
        if self.bytes == bytes && Arc::ptr_eq(provider, &self.witness.bank.get().provider) {
            Ok(())
        } else {
            Err(invalid())
        }
    }
    pub(crate) fn require_hold(&self, hold: &SourceMetadataBankHold) -> io::Result<()> {
        if self.witness.same_bank(hold) {
            Ok(())
        } else {
            Err(invalid())
        }
    }
    pub(crate) fn into_parts(self) -> (DiskMemoryLease, SourceMetadataWitness) {
        (self.lease, self.witness)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HistoryPhase {
    Queued,
    Prepared,
    Applied,
    Committed,
    Cancelled,
}
pub(crate) struct SourceMetadataHistory {
    account: AccountRef,
    admission: MetadataPreparation,
    replacement: Option<DiskMemoryLease>,
    phase: HistoryPhase,
    cleanup: MetadataAttempt<std::convert::Infallible>,
}
impl SourceMetadataHistory {
    pub(crate) fn prepare(&mut self) {
        let bank = self.account.get().bank.get();
        self.admission.acquire(
            &bank.provider,
            SourceMetadataPurpose::History,
            bank.quote.lane,
        );
        if self.admission.ready() {
            self.replacement = self.admission.take_for(
                &bank.provider,
                SourceMetadataPurpose::History,
                bank.quote.lane,
            );
            self.phase = HistoryPhase::Prepared;
        }
    }
    pub(crate) fn dispose(&mut self) {
        self.admission.dispose();
        if !self.admission.disposed() {
            return;
        }
        self.cleanup.run(|| {
            drop(self.replacement.take());
            Ok(())
        });
    }
    pub(crate) fn disposed(&self) -> bool {
        self.admission.disposed() && self.cleanup.succeeded()
    }
    pub(crate) fn cleanup(&self) -> TerminalObservation<'_, std::convert::Infallible> {
        self.cleanup.view()
    }
    pub(crate) fn ready(&self) -> bool {
        self.phase == HistoryPhase::Prepared
    }
    pub(crate) fn abortable(&self) -> bool {
        (self.phase == HistoryPhase::Cancelled
            || (matches!(self.phase, HistoryPhase::Queued | HistoryPhase::Prepared)
                && (self.admission.accepted() || self.admission.clean_history_refusal())))
            && !self.cleanup.failed()
    }
    pub(crate) fn abort(&mut self) -> io::Result<bool> {
        if !self.abortable() {
            return Ok(false);
        }
        self.dispose();
        if !self.disposed() {
            return Ok(false);
        }
        let account = self.account.get();
        let bank = account.bank.get();
        let state = account.state.lock().map_err(poisoned)?;
        if bank.fenced.load(Ordering::Acquire)
            || state.phase != AccountPhase::Active
            || !matches!(state.origin, Origin::Publication)
            || state.issued != [true; 2]
            || state.live != [true; 2]
        {
            return Err(invalid());
        }
        self.phase = HistoryPhase::Cancelled;
        Ok(true)
    }
    pub(crate) fn take_refusal(&mut self) -> Option<io::Error> {
        if self.phase != HistoryPhase::Cancelled {
            return None;
        }
        self.admission.take_clean_history_refusal()
    }
    pub(crate) fn preparation(&self) -> &MetadataPreparation {
        &self.admission
    }
    // Called only after actual native+byte exchange success. Reader -> pool ->
    // census ordered guards precede these bank/account guards. No callbacks.
    pub(crate) fn try_complete(&mut self) -> io::Result<Option<MetadataCompletion<'_>>> {
        if self.phase != HistoryPhase::Prepared || self.replacement.is_none() {
            return Err(invalid());
        }
        let account = self.account.get();
        let bank = account.bank.get();
        let Some(bank_state) = try_lock(&bank.state)? else {
            return Ok(None);
        };
        let Some(account_state) = try_lock(&account.state)? else {
            return Ok(None);
        };
        let lane = &bank_state.lanes[account.lane];
        if bank.fenced.load(Ordering::Acquire)
            || lane.ticket != account.ticket
            || lane.assignment != Assignment::Assigned
            || account_state.phase != AccountPhase::Active
            || !matches!(account_state.origin, Origin::Publication)
        {
            return Err(invalid());
        }
        Ok(Some(MetadataCompletion {
            bank,
            account,
            bank_state,
            account_state,
            replacement: &mut self.replacement,
            phase: &mut self.phase,
            applied: false,
            committed: false,
        }))
    }
}
pub(crate) struct MetadataCompletion<'a> {
    bank: &'a Bank,
    account: &'a Account,
    bank_state: MutexGuard<'a, BankState>,
    account_state: MutexGuard<'a, AccountState>,
    replacement: &'a mut Option<DiskMemoryLease>,
    phase: &'a mut HistoryPhase,
    applied: bool,
    committed: bool,
}
impl MetadataCompletion<'_> {
    pub(crate) fn apply(&mut self) {
        // All fallible work/guards/identity validation completed before here.
        self.account_state.phase = AccountPhase::Frozen;
        self.account_state.origin = Origin::History(
            self.replacement
                .take()
                .expect("prevalidated history credit"),
        );
        *self.phase = HistoryPhase::Applied;
        self.applied = true;
    }
    pub(crate) fn final_commit(&mut self) {
        let lane = &mut self.bank_state.lanes[self.account.lane];
        lane.assignment = Assignment::Free;
        // Deliberately DO NOT advance final-allocation retirement here. The
        // census converts the old Witness to Hold in this same guarded suffix.
        *self.phase = HistoryPhase::Committed;
        self.committed = true;
    }
}
impl Drop for MetadataCompletion<'_> {
    fn drop(&mut self) {
        if (self.applied && !self.committed) || std::thread::panicking() {
            self.bank.fenced.store(true, Ordering::Release);
            self.bank_state.lanes[self.account.lane].assignment = Assignment::Retained;
            self.account_state.phase = AccountPhase::Retained;
        }
    }
}
