#![cfg(unix)]
use kasumi_frozen_run::LiveDb;
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn import(bytes: &[u8], target: &Path) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kasumi-live-transfer"))
        .arg("import")
        .arg(target)
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
