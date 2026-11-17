//! Store files written by the deployed builds (`tests/deployed-format`): the
//! envelope in front of every node file, the audit archive objects, the file
//! keyrings and the backup destination marker. The envelope kinds are 1 for
//! the root, 2 for a segment and 4 for a directory arena.
#[path = "../../../tests/deployed-format/support.rs"]
mod support;

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use support::{FIXTURES, Fixtures, layout};
use uuid::Uuid;

const NODE: &str = "data/node.kv";
const ARCHIVES: &str = "data/tenant-audit-archives";

fn manifest(fixture: &str) -> serde_json::Value {
    serde_json::from_str(&support::manifest(fixture)).unwrap()
}

fn uuid(value: &serde_json::Value) -> Uuid {
    Uuid::parse_str(value.as_str().unwrap()).unwrap()
}

#[test]
fn every_deployed_node_file_has_its_ready_envelope_of_kind_1_2_or_4() {
    let fixtures = Fixtures::load();
    for fixture in FIXTURES {
        let database_id = uuid(&manifest(fixture)["installation"]["database_id"]);
        let mut kinds = BTreeSet::new();
        for name in fixtures.names(fixture, NODE) {
            let file = fixtures.file(fixture, &format!("{NODE}/{name}"));
            if file.len() < layout::ENVELOPE_BYTES {
                // An interrupted creation: every visible byte is zero or the
                // byte of this file's own Ready envelope.
                assert!(file.iter().all(|byte| *byte == 0), "{fixture} {name}");
                continue;
            }
            layout::check_envelope(&name, file, database_id.as_bytes());
            kinds.insert(file[32]);
        }
        assert_eq!(
            kinds,
            BTreeSet::from([
                layout::ROOT_KIND,
                layout::SEGMENT_KIND,
                layout::DIRECTORY_KIND
            ]),
            "{fixture}"
        );
        // The root file is its envelope and two slots, nothing else.
        layout::check_root_file(fixtures.file(fixture, &format!("{NODE}/root.kvroot")));
    }
}

#[test]
fn deployed_audit_archive_objects_bind_their_names_and_form_one_chain() {
    let fixtures = Fixtures::load();
    for fixture in FIXTURES {
        let manifest = manifest(fixture);
        let mut streams: BTreeMap<Uuid, Vec<kasumi_types::AuditArchiveReference>> = BTreeMap::new();
        for name in fixtures.names(fixture, ARCHIVES) {
            let object = name.strip_suffix(".audit").expect("a published object");
            let reference = kasumi_store::inspect_audit_object(
                fixtures.file(fixture, &format!("{ARCHIVES}/{name}")),
            )
            .unwrap_or_else(|error| panic!("{fixture} {name}: {error:#}"));
            reference.validate().unwrap();
            assert_eq!(reference.object.object_id.to_string(), object, "{fixture}");
            streams
                .entry(reference.stream_id)
                .or_default()
                .push(reference);
        }
        // Control's stream never reached its hot budget; the tenant's did.
        assert_eq!(streams.len(), 1, "{fixture}");
        let chain = streams.into_values().next().unwrap();
        let mut chain: Vec<_> = chain.iter().collect();
        chain.sort_by_key(|reference| reference.object.first_sequence);
        // The manifest was read just before the stop or kill; the killed
        // build's writer archived more after it.
        assert!(
            chain.len() as u64
                >= manifest["tenant_audit"]["archive_segments"]
                    .as_u64()
                    .unwrap(),
            "{fixture}"
        );
        assert_eq!(chain[0].object.first_sequence, 0, "{fixture}");
        assert!(chain[0].previous.is_none(), "{fixture}");
        for pair in chain.windows(2) {
            assert_eq!(
                pair[1].previous.as_ref(),
                Some(&pair[0].object),
                "{fixture}"
            );
            assert_eq!(
                pair[1].object.first_sequence, pair[0].object.next_sequence,
                "{fixture}"
            );
        }
        assert!(
            chain.last().unwrap().object.next_sequence
                >= manifest["tenant_audit"]["pruned_before"].as_u64().unwrap(),
            "{fixture}"
        );
    }
}

#[test]
fn deployed_file_keyrings_open() {
    let fixtures = Fixtures::load();
    for fixture in FIXTURES {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("installation");
        fixtures.extract(fixture, &root).unwrap();
        let keyrings = [
            "application-keys.json",
            "custody-keys.json",
            "control-keys.json",
            "control-custody-keys.json",
            "security-keys.json",
        ];
        for keyring in keyrings {
            kasumi_store::FileKeyProvider::open(root.join("operator").join(keyring))
                .unwrap_or_else(|error| panic!("{fixture} {keyring}: {error:#}"));
        }
    }
}

#[test]
fn the_deployed_backup_destination_marker_keeps_its_100_bytes() {
    let fixtures = Fixtures::load();
    for fixture in FIXTURES {
        let manifest = manifest(fixture);
        let marker = fixtures.file(fixture, "backups/local/kasumi-backup.marker");
        assert_eq!(marker.len(), 100, "{fixture}");
        assert_eq!(&marker[..8], b"KSMBND01");
        assert_eq!(marker[8..12], [0, 1, 0, 100]);
        assert_eq!(
            &marker[12..28],
            uuid(&manifest["installation"]["installation_id"]).as_bytes()
        );
        // The origin node of a standalone installation.
        assert_eq!(marker[28..36], 1u64.to_be_bytes());
        assert_ne!(marker[36..52], [0; 16]);
        assert_eq!(marker[68..], Sha256::digest(&marker[..68])[..]);
    }
}
