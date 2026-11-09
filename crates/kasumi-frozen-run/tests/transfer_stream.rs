#![cfg(unix)]
use kasumi_frozen_run::LiveDb;
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn import(bytes: &[u8], target: &Path) -> std::process::Output {
    run_import(bytes, target, None)
}

fn run_import(bytes: &[u8], target: &Path, rows: Option<&str>) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kasumi-live-transfer"))
        .arg(if rows.is_some() {
            "import-filtered"
        } else {
            "import"
        })
        .arg(target)
        .args(rows)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn complete_trailer_is_required_for_publication_and_verify_rejects_wrong_source() {
    // Zero-length keys and values are distinct legal records.
    let mut payload = Vec::new();
    for field in [b"".as_slice(), b"abc", b"k", b""] {
        payload.extend((field.len() as u32).to_be_bytes());
        payload.extend(field);
    }
    let digest = Sha256::digest(&payload);
    let raw = [
        b"KSRKRAW1".as_slice(),
        &payload,
        &u32::MAX.to_be_bytes(),
        &2u64.to_be_bytes(),
        &4u64.to_be_bytes(),
        &digest,
    ]
    .concat();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("valid");
    assert!(import(&raw, &target).status.success());
    let filtered = dir.path().join("filtered");
    assert!(run_import(&raw, &filtered, Some("2")).status.success());
    let export = Command::new(env!("CARGO_BIN_EXE_kasumi-live-transfer"))
        .arg("export-read-only")
        .arg(filtered)
        .output()
        .unwrap();
    assert!(export.status.success());
    assert_eq!(export.stdout, raw);
    assert!(
        !run_import(&raw, &dir.path().join("wrong-count"), Some("3"))
            .status
            .success()
    );
    let readonly = Command::new(env!("CARGO_BIN_EXE_kasumi-live-transfer"))
        .arg("export-read-only")
        .arg(&target)
        .output()
        .unwrap();
    assert!(readonly.status.success());
    assert_eq!(readonly.stdout, raw);
    assert!(
        String::from_utf8(readonly.stderr)
            .unwrap()
            .contains("\"read_only\":true")
    );
    assert!(!import(&raw, &target).status.success());
    assert_eq!(
        LiveDb::open(&target).unwrap().get(b"k").unwrap(),
        Some(Vec::new())
    );
    let executable = env!("CARGO_BIN_EXE_kasumi-live-transfer");
    let verify = |n: &str| {
        Command::new(executable)
            .arg("verify")
            .arg(&target)
            .arg(n)
            .arg(hex::encode(digest))
            .output()
            .unwrap()
    };
    assert!(verify("2").status.success());
    assert!(!verify("1").status.success());
    let mut corrupt = raw.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut trailing = raw.clone();
    trailing.push(0);
    for (n, bad) in [
        &raw[..raw.len() - 1],
        &raw[..8 + payload.len()],
        &corrupt,
        &trailing,
    ]
    .into_iter()
    .enumerate()
    {
        let out = dir.path().join(format!("bad-{n}"));
        assert!(!import(bad, &out).status.success());
        let mut reopened = LiveDb::open(out).unwrap();
        assert_eq!(reopened.sequence(), 0);
        assert!(reopened.get(b"").unwrap().is_none());
    }
}

#[test]
fn empty_database_has_no_importable_export() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty");
    drop(LiveDb::create(&path).unwrap());
    let output = Command::new(env!("CARGO_BIN_EXE_kasumi-live-transfer"))
        .arg("export-read-only")
        .arg(path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("empty live database")
    );
}
