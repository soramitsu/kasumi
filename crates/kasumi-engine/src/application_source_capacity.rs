//! The actual Cell/DTO lane charge. Native/report rights remain owned by Store.
//! No runtime cohort is constructed until its accepted-shape seam is installed.
use super::*;
use crate::admission::NodeAdmission;
use anyhow::{Context as _, Result, ensure};
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ticket {
    lane: usize,
    serial: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    Available,
    Assigned(u64),
    Retained(u64),
}
struct State {
    serial: u64,
    lanes: [Lane; 2],
    sealed: bool,
}

/// An Engine component of the one source cohort. Its two lane portions fund
/// real Cell/credit/registry/retained-proof allocations, never native buffers or
/// Store reports a second time. Every assigned credit keeps this actual grant.
pub(in crate::application_sources) struct LaneFunding {
    admission: Arc<NodeAdmission>,
    lane_bytes: u64,
    state: Mutex<State>,
    _grant: Reservation,
}
impl LaneFunding {
    #[cfg(test)]
    pub(in crate::application_sources) fn reserve(
        admission: Arc<NodeAdmission>,
        lane_bytes: u64,
    ) -> Result<LaneFundingRef> {
        let fixed = super::super::allocated(
            std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>(),
        )?;
        let bytes = lane_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(fixed))
            .context("source lane funding quote overflow")?;
        let grant = admission.reserve_document_source(bytes)?;
        Ok(LaneFundingRef(Some(Arc::new(Self {
            admission,
            lane_bytes,
            state: Mutex::new(State {
                serial: 0,
                lanes: [Lane::Available; 2],
                sealed: false,
            }),
            _grant: grant,
        }))))
    }
    fn available_lane(&self) -> Result<usize> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        ensure!(!state.sealed, "source lane funding is sealed");
        state
            .lanes
            .iter()
            .position(|lane| *lane == Lane::Available)
            .context("source lanes are still retained")
    }
    fn release(&self, ticket: Ticket) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.lanes[ticket.lane] == Lane::Assigned(ticket.serial) {
            state.lanes[ticket.lane] = Lane::Available;
        } else {
            state.sealed = true;
            state.lanes[ticket.lane] = Lane::Retained(ticket.serial);
        }
    }
    fn retain(&self, ticket: Ticket) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.sealed = true;
        state.lanes[ticket.lane] = Lane::Retained(ticket.serial);
    }
    pub(in crate::application_sources) fn seal(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .sealed = true;
    }
}

/// No Weak/raw escape. The last owner frees its Arc allocation before the
/// moved bank retires the real standing Reservation, including failure tails.
pub(in crate::application_sources) struct LaneFundingRef(Option<Arc<LaneFunding>>);
impl std::ops::Deref for LaneFundingRef {
    type Target = LaneFunding;
    fn deref(&self) -> &Self::Target {
        self.0.as_deref().expect("source lane funding")
    }
}
impl Clone for LaneFundingRef {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl Drop for LaneFundingRef {
    fn drop(&mut self) {
        if let Some(funding) = self.0.take() {
            drop(Arc::into_inner(funding));
        }
    }
}
impl LaneFundingRef {
    pub(super) fn assign_available(&self) -> Result<PublicationCredit> {
        self.assign(self.available_lane()?)
    }
    pub(super) fn assign(&self, lane: usize) -> Result<PublicationCredit> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        ensure!(!state.sealed, "source lane funding is sealed");
        ensure!(
            state.lanes.get(lane) == Some(&Lane::Available),
            "source lane is not positively available"
        );
        let serial = state
            .serial
            .checked_add(1)
            .context("source lane ticket exhausted")?;
        state.serial = serial;
        state.lanes[lane] = Lane::Assigned(serial);
        Ok(PublicationCredit {
            funding: self.clone(),
            ticket: Ticket { lane, serial },
            state: Mutex::new(CreditState {
                class: CreditClass::Publication,
                history: None,
                retirement_proven: false,
            }),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CreditClass {
    Publication,
    PreparingHistory,
    RetiringHistory,
    History,
    Retained,
}
struct CreditState {
    class: CreditClass,
    history: Option<Reservation>,
    retirement_proven: bool,
}
/// This object resides inside the same SourceCredit allocation as an ordinary
/// grant. All Cell, view, diagnostic and Weak tails therefore share its account.
pub(super) struct PublicationCredit {
    funding: LaneFundingRef,
    ticket: Ticket,
    state: Mutex<CreditState>,
}
impl PublicationCredit {
    /// Acquire actual ordinary Cell/DTO funding before native history preparation.
    /// The caller serializes a source's public escape, and retains this account
    /// through any incomplete native/report exchange. No provider runs under locks.
    pub(super) fn prepare_history(&self) -> Result<bool> {
        {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.class == CreditClass::History {
                return Ok(false);
            }
            if state.class == CreditClass::PreparingHistory {
                return Ok(true);
            }
            ensure!(
                state.class == CreditClass::Publication && !state.retirement_proven,
                "source history funding is not pristine"
            );
        }
        let grant = self
            .funding
            .admission
            .reserve_document_source(self.funding.lane_bytes)?;
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        ensure!(
            state.class == CreditClass::Publication && !state.retirement_proven,
            "source history funding changed during admission"
        );
        state.history = Some(grant);
        state.class = CreditClass::PreparingHistory;
        Ok(true)
    }
    /// Only the actual complete native+metadata+census history result grants
    /// this authority. Replacement Engine allocations now spend the standing
    /// lane; the old account and every alias retain this actual ordinary grant.
    pub(super) fn commit_history(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.class, CreditClass::PreparingHistory);
        assert!(state.history.is_some());
        state.class = CreditClass::History;
        drop(state);
        self.funding.release(self.ticket);
    }
    /// Call only after positive precommit native/report/census rollback. Refund
    /// the proposed Engine grant outside the guard. An unwinding destructor is
    /// an unknown retirement and permanently withholds this publication ticket.
    pub(super) fn abort_history(&self) -> std::thread::Result<()> {
        let grant = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            assert_eq!(state.class, CreditClass::PreparingHistory);
            state.class = CreditClass::RetiringHistory;
            state.history.take().expect("prepared history charge")
        };
        let retired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(grant)));
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if retired.is_ok() {
            state.class = CreditClass::Publication;
        } else {
            state.class = CreditClass::Retained;
            self.funding.retain(self.ticket);
        }
        retired
    }
    /// Positive native close/registered disposition is necessary, but does not
    /// return the ticket here. Only final SourceCredit backing destruction after
    /// every Cell/view/diagnostic/Weak allocation tail can return a publication lane.
    pub(super) fn prove_retirement(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.class == CreditClass::Publication {
            state.retirement_proven = true;
        }
    }
    pub(super) fn lane(&self) -> usize {
        self.ticket.lane
    }
    pub(super) fn seal(&self) {
        self.funding.seal();
    }
    #[cfg(test)]
    pub(super) fn is_history(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .class
            == CreditClass::History
    }
}
impl Drop for PublicationCredit {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        match state.class {
            CreditClass::Publication if state.retirement_proven => {
                self.funding.release(self.ticket)
            }
            CreditClass::History => {}
            _ => self.funding.retain(self.ticket),
        }
        // Field drop retires the actual history grant after all payload/weak
        // tails and after the above classification. It never refunds a live lane.
    }
}

#[cfg(test)]
#[path = "application_source_capacity_tests.rs"]
mod tests;
