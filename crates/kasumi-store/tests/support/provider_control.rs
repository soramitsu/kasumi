//! Private handshake between an opt-in libtest and a release process owner.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{env, fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

pub fn supervised() -> bool {
    env::var_os("KASUMI_PROVIDER_CONTROL").is_some()
}

pub fn request(event: &str, parameters: Value) -> Result<()> {
    let root = PathBuf::from(
        env::var_os("KASUMI_PROVIDER_CONTROL").context("missing provider controller")?,
    );
    let path = root.join(event);
    let temporary = root.join(format!("{event}.partial"));
    let mut file = OpenOptions::new()
        .mode(0o600)
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    serde_json::to_writer(&mut file, &parameters)?;
    file.flush()?;
    file.sync_all()?;
    std::fs::rename(&temporary, &path)?;
    let mut reply = String::new();
    let count = std::io::stdin().read_line(&mut reply)?;
    if event == "complete" {
        ensure!(count == 0, "provider controller did not close its input");
    } else {
        ensure!(
            reply.trim_end() == event,
            "provider controller did not confirm the requested phase"
        );
    }
    Ok(())
}
