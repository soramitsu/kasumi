//! Concrete ownership for local administrative topology observations and the
//! configured peer-map replacement. No owner exports a raw owned map or pins a
//! Generation after completion. Quorum topology/other command producers remain
//! separate corridors; these grants never retroactively adopt their inputs.
use super::*;
use kasumi_engine::control::{ControlNode, VersionedTopology};
use kasumi_engine::{
    AdmittedOutput,
    admission::{NodeAdmission, Reservation},
};
use kasumi_query::{QueryCancellation, QueryWorkspace};
use std::{mem::size_of, ops::Deref};

pub(crate) struct CommittedTopology(AdmittedOutput<VersionedTopology>);
impl Deref for CommittedTopology {
    type Target = ControlTopology;
    fn deref(&self) -> &Self::Target {
        &self.0.topology
    }
}

fn overflow() -> kasumi_types::Error {
    kasumi_types::Error::new(
        kasumi_types::ErrorCode::ResourceExhausted,
        "administrative topology workspace overflow",
    )
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(|| overflow().into())
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).ok_or_else(|| overflow().into())
}
fn backing(n: usize) -> Result<u64> {
    if n == 0 {
        return Ok(0);
    }
    if n > isize::MAX as usize {
        return Err(overflow().into());
    }
    n.checked_next_power_of_two()
        .and_then(|n| n.checked_add(64))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(|| overflow().into())
}
fn tree<K, V>(entries: usize) -> Result<u64> {
    let bytes = size_of::<K>()
        .checked_add(size_of::<V>())
        .and_then(|n| n.checked_mul(11))
        .and_then(|n| n.checked_add(16 * size_of::<usize>()))
        .ok_or_else(overflow)?;
    mul(u64::try_from(entries)?, backing(bytes)?)
}
fn vector<T>(entries: usize) -> Result<u64> {
    if entries == 0 {
        return Ok(0);
    }
    // Iterator collection/growth plus BTree bulk-build sorting can coexist.
    // Four doubled-capacity buffers cover old/new RawVec and sort scratch.
    mul(
        backing(
            size_of::<T>()
                .checked_mul(entries.max(4))
                .and_then(|n| n.checked_mul(2))
                .ok_or_else(overflow)?,
        )?,
        4,
    )
}
pub(super) struct Failure {
    original: anyhow::Error,
    _reservation: Reservation,
}
impl Failure {
    pub(super) fn validation_error(&self) -> Option<&kasumi_types::Error> {
        self.original.downcast_ref()
    }
}
impl std::fmt::Debug for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AdministrativeTopologyFailure")
            .field(&self.original)
            .finish()
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.original, f)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}
fn failure(original: anyhow::Error, mut reservation: Reservation) -> anyhow::Error {
    reservation.retain(u64::MAX);
    anyhow::Error::new(Failure {
        original,
        _reservation: reservation,
    })
}
fn fixed() -> Result<u64> {
    // Concrete fixed errors, cancellation Arc, anyhow owner and growth/shrink
    // slack. Optional backtrace and arbitrary external diagnostics are separate.
    add(
        add(backing(kasumi_types::Error::MAX_MESSAGE_BYTES)?, 4096)?,
        add(
            backing(
                QueryCancellation::shared_state_bytes()
                    .checked_add(2 * size_of::<usize>())
                    .ok_or_else(overflow)?,
            )?,
            mul(
                backing(
                    size_of::<Failure>()
                        + size_of::<Option<std::backtrace::Backtrace>>()
                        + size_of::<[usize; 8]>(),
                )?,
                2,
            )?,
        )?,
    )
}
fn nodes_retained(nodes: &BTreeMap<u64, ControlNode>) -> Result<u64> {
    nodes
        .values()
        .try_fold(tree::<u64, ControlNode>(nodes.len())?, |total, node| {
            let mut total = add(
                total,
                add(
                    backing(node.endpoint.capacity())?,
                    backing(node.failure_domain.capacity())?,
                )?,
            )?;
            total = add(total, tree::<String, ()>(node.certificate_pins.len())?)?;
            for pin in &node.certificate_pins {
                total = add(total, backing(pin.capacity())?)?;
            }
            Ok(total)
        })
}
fn nodes_clone(nodes: &BTreeMap<u64, ControlNode>) -> Result<u64> {
    nodes.values().try_fold(
        add(
            tree::<u64, ControlNode>(nodes.len())?,
            vector::<(u64, ControlNode)>(nodes.len())?,
        )?,
        |total, node| {
            let mut total = add(
                total,
                add(
                    backing(node.endpoint.len())?,
                    backing(node.failure_domain.len())?,
                )?,
            )?;
            total = add(
                total,
                add(
                    tree::<String, ()>(node.certificate_pins.len())?,
                    vector::<String>(node.certificate_pins.len())?,
                )?,
            )?;
            for pin in &node.certificate_pins {
                total = add(total, backing(pin.len())?)?;
            }
            Ok(total)
        },
    )
}
fn configured_quote(replication: &crate::runtime::ReplicationConfig) -> Result<u64> {
    let mut total = add(
        tree::<u64, ControlNode>(replication.peers.len())?,
        vector::<(u64, ControlNode)>(replication.peers.len())?,
    )?;
    for peer in &replication.peers {
        // Actual control_nodes performs Url::parse -> Origin (scheme/host
        // clones) -> ascii_serialization. Four complete parser peaks cover the
        // retained normalized endpoint plus these overlapping copies/growth.
        total = add(
            total,
            add(
                mul(
                    ControlTopology::endpoint_workspace_bytes(&peer.endpoint)?,
                    4,
                )?,
                backing(64)?,
            )?,
        )?;
        total = add(total, backing(peer.failure_domain.len())?)?;
        total = add(
            total,
            add(
                tree::<String, ()>(peer.certificate_pins.len())?,
                vector::<String>(peer.certificate_pins.len())?,
            )?,
        )?;
        for pin in &peer.certificate_pins {
            total = add(total, backing(pin.len())?)?;
        }
    }
    add(total, fixed()?)
}

pub(super) struct ConfiguredNodes {
    nodes: BTreeMap<u64, ControlNode>,
    reservation: Reservation,
}
impl Deref for ConfiguredNodes {
    type Target = BTreeMap<u64, ControlNode>;
    fn deref(&self) -> &Self::Target {
        &self.nodes
    }
}
struct NodesWork {
    nodes: Option<BTreeMap<u64, ControlNode>>,
    cancellation: QueryCancellation,
    reservation: Reservation,
}
impl NodesWork {
    fn new(node: &Arc<NodeAdmission>, quote: u64) -> Result<Self> {
        let reservation = node.reserve(quote, None)?;
        Ok(Self {
            nodes: None,
            cancellation: QueryCancellation::default(),
            reservation,
        })
    }
    fn fail(self, error: anyhow::Error) -> anyhow::Error {
        let Self {
            nodes,
            cancellation,
            reservation,
        } = self;
        drop(nodes);
        drop(cancellation);
        failure(error, reservation)
    }
    fn finish(self) -> Result<ConfiguredNodes> {
        // A later replacement workspace growth can be refused. Its original
        // diagnostic must already have credit, including for an empty map.
        let retained = match nodes_retained(self.nodes.as_ref().expect("constructed peer map"))
            .and_then(|retained| add(retained, fixed()?))
        {
            Ok(retained) => retained,
            Err(error) => return Err(self.fail(error)),
        };
        let Self {
            nodes,
            cancellation,
            mut reservation,
        } = self;
        drop(cancellation);
        reservation.retain(retained);
        Ok(ConfiguredNodes {
            nodes: nodes.expect("constructed peer map"),
            reservation,
        })
    }
}
impl Administration {
    pub(crate) fn committed_topology(&self) -> Result<CommittedTopology> {
        Ok(CommittedTopology(ControlPlane::local_topology(
            &self.control,
        )?))
    }
    pub(super) fn configured_nodes(&self) -> Result<ConfiguredNodes> {
        let selection = ControlPlane::select_local(&self.control)?;
        selection.check_admission(&self.admission)?;
        let local = if self.config.replication.is_none() {
            Some(self.committed_topology()?)
        } else {
            None
        };
        let quote = if let Some(replication) = &self.config.replication {
            configured_quote(replication)?
        } else {
            add(
                nodes_clone(&local.as_ref().expect("local source").nodes)?,
                fixed()?,
            )?
        };
        let mut work = NodesWork::new(&self.admission, quote)?;
        let result = (|| {
            self.admission.check_release(&work.cancellation)?;
            work.nodes = Some(if let Some(replication) = &self.config.replication {
                replication.control_nodes()?
            } else {
                local.as_ref().expect("local source").nodes.clone()
            });
            self.admission.check_release(&work.cancellation)?;
            selection.check_access()?;
            Ok(())
        })();
        match result {
            Ok(()) => work.finish(),
            Err(error) => Err(work.fail(error)),
        }
    }
}

// This exact consumer transfers the configured map and its original grant.
// The caller's quorum topology/tenant map remains a separate source corridor.
// Canonical Engine replace_topology owns its new JSON under a separate grant.
pub(super) struct PeerPoolUpdate {
    topology: Option<ControlTopology>,
    reservation: Reservation,
}
fn validation_workspace(topology: &ControlTopology) -> Result<u64> {
    let mut pins = 0usize;
    let mut url = 0;
    for node in topology.nodes.values() {
        pins = pins
            .checked_add(node.certificate_pins.len())
            .ok_or_else(overflow)?;
        url = url.max(ControlTopology::endpoint_workspace_bytes(&node.endpoint)?);
    }
    let voters = topology
        .tenants
        .values()
        .map(|route| route.voters.len())
        .max()
        .unwrap_or(0);
    add(
        add(
            tree::<&String, ()>(pins)?,
            url.max(add(tree::<&String, ()>(voters)?, backing(36)?)?),
        )?,
        fixed()?,
    )
}
impl ConfiguredNodes {
    pub(super) fn replacement(self, mut topology: ControlTopology) -> Result<PeerPoolUpdate> {
        let Self { nodes, reservation } = self;
        topology.nodes = nodes;
        let mut update = PeerPoolUpdate {
            topology: Some(topology),
            reservation,
        };
        let result = (|| {
            let topology = update.topology.as_ref().expect("replacement");
            let retained = nodes_retained(&topology.nodes)?;
            update
                .reservation
                .ensure_peak(add(retained, validation_workspace(topology)?)?)?;
            // Preserve rejection before the management Started audit event.
            topology.validate()?;
            // Publication can still return a concrete diagnostic. Keep its
            // original Error/anyhow Failure backing even for an empty map;
            // only the completed validator's transient scratch retires here.
            update.reservation.retain(add(retained, fixed()?)?);
            Ok(())
        })();
        match result {
            Ok(()) => Ok(update),
            Err(error) => Err(update.fail(error)),
        }
    }
}
impl PeerPoolUpdate {
    fn fail(self, error: anyhow::Error) -> anyhow::Error {
        let Self {
            topology,
            reservation,
        } = self;
        drop(topology);
        failure(error, reservation)
    }
    pub(super) async fn publish(
        mut self,
        plane: &ControlPlane,
        context: RequestContext,
        expected: Precondition,
        key: String,
    ) -> Result<()> {
        // Before this await can yield, replace_topology's synchronous factory
        // consumes/destroys the source topology and transfers its new JSON into
        // an Engine input owner. Unpolled self keeps source before grant; unwind
        // destroys the active child before this enclosing owner.
        let result = plane
            .replace_topology(
                context,
                self.topology.take().expect("replacement"),
                expected,
                key,
            )
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error) => Err(self.fail(error.into())),
        }
    }
}

#[cfg(test)]
#[path = "administration_topology_tests.rs"]
mod tests;
