//! In-memory changes newer than the selected immutable levels. None is a deletion.
pub(super) type Delta = std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>;
