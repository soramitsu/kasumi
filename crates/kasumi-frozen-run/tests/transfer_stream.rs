#![cfg(unix)]
use kasumi_frozen_run::LiveDb;
use sha2::{Digest, Sha256};
use std::{
    io::{ErrorKind, Write},
    path::Path,
    process::{Command, Stdio},
};

fn import(bytes: &[u8], target: &Path) -> std::process::Output {
    run_import(bytes, target, None)
}

fn run_import(bytes: &[u8], target: &Path, rows: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kasumi-live-transfer"));
    command
        .arg(if rows.is_some() {
            "import-filtered"
        } else {
            "import"
        })
        .arg(target)
        .args(rows);
    pipe_input(&mut command, bytes)
}

fn pipe_input(command: &mut Command, bytes: &[u8]) -> std::process::Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let written = child.stdin.take().unwrap().write_all(bytes);
    let output = child.wait_with_output().unwrap();
    if let Err(error) = written {
        // Rejected arguments and existing targets may close stdin before
        // the parent runs. Require the importer to have returned its error.
        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
        assert_eq!(output.status.code(), Some(1));
    }
    output
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
    let existing = import(&raw, &target);
    assert_eq!(existing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&existing.stderr).contains("AlreadyExists"));
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
fn a_trailing_zstd_imports_the_same_rows_into_a_zstandard_database() {
    let mut payload = Vec::new();
    for n in 0..400u32 {
        let key = format!("account/{n:06}");
        let value = format!(
            "{:064x}",
            u128::from(n).wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835)
        );
        for field in [key.as_bytes(), value.as_bytes()] {
            payload.extend((field.len() as u32).to_be_bytes());
            payload.extend(field);
        }
    }
    let digest = Sha256::digest(&payload);
    let logical = (payload.len() - 400 * 8) as u64;
    let raw = [
        b"KSRKRAW1".as_slice(),
        &payload,
        &u32::MAX.to_be_bytes(),
        &400u64.to_be_bytes(),
        &logical.to_be_bytes(),
        &digest,
    ]
    .concat();
    let executable = env!("CARGO_BIN_EXE_kasumi-live-transfer");
    let run =
        |arguments: &[&std::ffi::OsStr]| pipe_input(Command::new(executable).args(arguments), &raw);
    let dir = tempfile::tempdir().unwrap();
    let [plain, zstd, filtered, unknown] =
        ["plain", "zstd", "filtered", "unknown"].map(|name| dir.path().join(name));
    let word = std::ffi::OsStr::new;
    assert!(run(&[word("import"), plain.as_os_str()]).status.success());
    assert!(
        run(&[word("import"), zstd.as_os_str(), word("zstd")])
            .status
            .success()
    );
    assert!(
        run(&[
            word("import-filtered"),
            filtered.as_os_str(),
            word("400"),
            word("zstd")
        ])
        .status
        .success()
    );
    // Any other trailing word is a usage error, before anything is created.
    let invalid = run(&[word("import"), unknown.as_os_str(), word("snappy")]);
    assert_eq!(invalid.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("usage: kasumi-live-transfer"));
    assert!(!unknown.exists());
    for (path, codec) in [
        (&plain, kasumi_frozen_run::BlockCodec::Lz4),
        (&zstd, kasumi_frozen_run::BlockCodec::Zstd),
        (&filtered, kasumi_frozen_run::BlockCodec::Zstd),
    ] {
        let mut db = LiveDb::open(path).unwrap();
        assert_eq!(db.block_codec(), codec);
        assert_eq!(db.sequence(), 1);
        assert!(db.get(b"account/000399").unwrap().is_some());
        drop(db);
        let export = Command::new(executable)
            .arg("export-read-only")
            .arg(path)
            .output()
            .unwrap();
        assert!(export.status.success());
        assert_eq!(export.stdout, raw);
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
