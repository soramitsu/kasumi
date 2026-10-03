use super::*;
use crate::{
    FileKeyProvider, allocation_tests::measure_requested, private_files,
    test_utils::private_tempdir,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::collections::BTreeMap;

#[test]
fn file_key_open_workspace_is_checked_and_allocation_free() {
    for bytes in [0, 1, 255, 4096, 1 << 20] {
        let (value, allocations, requested) =
            measure_requested(|| FileKeyProvider::open_input_workspace_bytes(bytes));
        assert!(value.unwrap() > MAX_KEYRING_BYTES as u64);
        assert_eq!((allocations, requested), (0, 0));
    }
    let (value, allocations, requested) =
        measure_requested(|| FileKeyProvider::open_input_workspace_bytes(usize::MAX));
    assert_eq!(value.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!((allocations, requested), (0, 0));
}

fn keyring(versions: u64) -> Vec<u8> {
    serde_json::to_vec(&super::super::Keyring {
        format: 1,
        id: uuid::Uuid::from_u128(7),
        domain: "synthetic-application".into(),
        active: versions,
        versions: (1..=versions)
            .map(|version| (version, STANDARD.encode([7u8; 32])))
            .collect::<BTreeMap<_, _>>(),
    })
    .unwrap()
}

#[test]
fn file_key_open_workspace_covers_real_bounded_factory() -> anyhow::Result<()> {
    const MARKER: &str = "KASUMI_FILE_KEY_FACTORY_CENSUS";
    const NAME: &str =
        "file_keys::workspace::tests::file_key_open_workspace_covers_real_bounded_factory";
    if std::env::var(MARKER).as_deref() != Ok(NAME) {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(MARKER, NAME)
            .env("RUST_BACKTRACE", "0")
            .env("RUST_LIB_BACKTRACE", "0")
            .output()?;
        anyhow::ensure!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "isolated file-key factory census failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let root = private_tempdir()?;
    let path = root.path().join("synthetic-keyring.json");
    let bound =
        FileKeyProvider::open_input_workspace_bytes(path.as_os_str().as_encoded_bytes().len())?;
    let cases = [
        (keyring(1), true),
        (keyring(12), true),
        (keyring(1000), true),
        (keyring(10_000), true),
        (vec![b' '; MAX_KEYRING_BYTES + 1], false),
        (b"{}".to_vec(), false),
        (
            serde_json::to_vec(&serde_json::json!({"format": "\u{1}".repeat(32 << 10)}))?,
            false,
        ),
        (
            serde_json::to_vec(&serde_json::json!({"\u{1}".repeat(32 << 10): null}))?,
            false,
        ),
    ];
    let mut first = true;
    for (bytes, valid) in cases {
        if first {
            private_files::create(&path, &bytes)?;
            first = false;
        } else {
            private_files::replace(&path, &bytes)?;
        }
        let (input, _allocations, requested) =
            measure_requested(|| FileKeyProvider::prepare_open(&path));
        assert!(
            requested as u64 <= bound,
            "bounded read {requested} > {bound}"
        );
        let Ok(input) = input else {
            assert!(!valid);
            continue;
        };
        let (decode_bound, allocations, requested) = measure_requested(|| input.workspace_bytes());
        assert_eq!((allocations, requested), (0, 0), "decode quote allocated");
        let decode_bound = decode_bound?;
        if bytes.len() < 1024 {
            assert!(
                decode_bound < 512 << 10,
                "tiny input kept the worst-case floor"
            );
        }
        let (success, _allocations, requested) = measure_requested(|| {
            let result = input.finish();
            let success = result.is_ok();
            if let Ok(provider) = &result {
                assert!(provider.key_ref().ends_with("/synthetic-application"));
                assert!(provider.retained_workspace_bytes().unwrap() < 4096);
            }
            drop(result);
            success
        });
        assert_eq!(success, valid);
        assert!(
            requested as u64 <= decode_bound,
            "decode {requested} > {decode_bound}"
        );
    }
    for replacement in [
        serde_json::json!("A".repeat(MAX_KEYRING_BYTES / 2)),
        serde_json::json!("not-base64"),
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&keyring(1))?;
        value["versions"]["1"] = replacement;
        let bytes = serde_json::to_vec(&value)?;
        private_files::replace(&path, &bytes)?;
        let input = FileKeyProvider::prepare_open(&path)?;
        let bound = input.workspace_bytes()?;
        let (success, _, requested) = measure_requested(|| {
            let result = input.finish();
            let success = result.is_ok();
            drop(result);
            success
        });
        assert!(!success);
        assert!(requested as u64 <= bound);
    }
    Ok(())
}

#[test]
fn prepared_file_input_selects_one_generation_and_preserves_validation_errors() -> anyhow::Result<()>
{
    let root = private_tempdir()?;
    let path = root.path().join("synthetic-keyring.json");
    let original = keyring(1);
    private_files::create(&path, &original)?;
    let selected = FileKeyProvider::prepare_open(&path)?;
    let mut replacement: super::super::Keyring = serde_json::from_slice(&original)?;
    replacement.id = uuid::Uuid::from_u128(8);
    private_files::replace(&path, &serde_json::to_vec(&replacement)?)?;
    let opened = selected.finish()?;
    assert!(
        opened
            .key_ref()
            .contains(&uuid::Uuid::from_u128(7).to_string())
    );
    assert!(
        FileKeyProvider::open(&path)?
            .key_ref()
            .contains(&replacement.id.to_string())
    );

    let mut cases = vec![b"{}".to_vec(), vec![]];
    let mut noncanonical = original.clone();
    noncanonical.push(b' ');
    cases.push(noncanonical);
    for id in [uuid::Uuid::nil(), uuid::Uuid::from_u128(7)] {
        replacement.id = id;
        replacement.active = if id.is_nil() { 1 } else { 2 };
        cases.push(serde_json::to_vec(&replacement)?);
    }
    for bytes in cases {
        private_files::replace(&path, &bytes)?;
        let legacy = FileKeyProvider::open(&path).err().expect("invalid input");
        let staged = FileKeyProvider::prepare_open(&path)?
            .finish()
            .err()
            .expect("invalid input");
        assert_eq!(legacy.to_string(), staged.to_string());
    }
    Ok(())
}
