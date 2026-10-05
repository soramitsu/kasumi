use super::*;

struct ScanWorkspace {
    memory: Arc<TestDiskMemory>,
    bytes: u64,
    charge: Option<DiskMemoryLease>,
    rows: usize,
}
impl ScanWorkspace {
    fn new(memory: Arc<TestDiskMemory>) -> Self {
        Self {
            memory,
            bytes: 0,
            charge: None,
            rows: 0,
        }
    }
    fn prepare(&mut self, bytes: u64) -> Result<()> {
        if bytes > self.bytes {
            let replacement = self.memory.clone().reserve_installed(bytes)?;
            self.charge = Some(replacement);
            self.bytes = bytes;
        }
        Ok(())
    }
}

#[tokio::test]
async fn paired_constructor_visit_uses_same_registered_root_and_actual_row_quote() -> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.write(b"old")?;
    let mut old = fixture.session(64)?;
    let id = old.registered_reader_id();
    let newer = vec![b'n'; 1024];
    fixture.write(&newer)?;
    let mut workspace = ScanWorkspace::new(fixture.memory.clone());
    let ceiling = plaintext_get_workspace_bytes(
        fixture.stores.custody().store().tenant().len(),
        7,
        4096,
        32 << 20,
    )?;
    old.custody_visit_with_workspace(
        "payload",
        32 << 20,
        &mut workspace,
        ScanWorkspace::prepare,
        |workspace, bounds, key, value| {
            assert!(workspace.charge.is_some());
            assert!(workspace.bytes < ceiling);
            assert_eq!(key, b"key");
            assert_eq!(value, b"old");
            assert!(
                bounds
                    .application_value_bound("payload", b"key", 64)?
                    .is_some()
            );
            workspace.rows += 1;
            Ok(())
        },
    )?;
    assert_eq!(workspace.rows, 1);
    assert_eq!(old.registered_reader_id(), id);
    assert_eq!(
        old.application_get("payload", b"key", 64)?,
        Some(b"old".as_slice())
    );
    let mut current = fixture.session(newer.len())?;
    assert_eq!(
        current.custody_get("payload", b"key", newer.len())?,
        Some(newer.as_slice())
    );
    old.close()?;
    current.close()?;
    drop(workspace);
    fixture.close().await
}

#[derive(Debug)]
struct RejectedScan(Arc<()>);
impl std::fmt::Display for RejectedScan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original constructor row rejection")
    }
}
impl std::error::Error for RejectedScan {}

#[tokio::test]
async fn paired_constructor_visit_preserves_original_callback_and_admission_errors() -> Result<()> {
    for before_decode in [true, false] {
        let fixture = Fixture::new(0).await?;
        fixture.write(b"secret")?;
        let mut session = fixture.session(64)?;
        let marker = Arc::new(());
        let mut workspace = ScanWorkspace::new(fixture.memory.clone());
        let result = session.custody_visit_with_workspace(
            "payload",
            64,
            &mut workspace,
            |workspace, bytes| {
                if before_decode {
                    return Err(RejectedScan(marker.clone()).into());
                }
                workspace.prepare(bytes)
            },
            |workspace, _, _, _| {
                workspace.rows += 1;
                Err(RejectedScan(marker.clone()).into())
            },
        );
        let original = session.finish(result).unwrap_err();
        assert!(Arc::ptr_eq(
            &original.downcast_ref::<RejectedScan>().unwrap().0,
            &marker
        ));
        assert_eq!(workspace.rows, usize::from(!before_decode));
        assert_eq!(workspace.charge.is_some(), !before_decode);
        drop((original, workspace));
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn paired_constructor_visit_checks_peer_access_empty_scans_and_callback_expiry() -> Result<()>
{
    for namespace in ["payload", "empty"] {
        let fixture = Fixture::new(8 << 20).await?;
        fixture.write(b"secret")?;
        let mut session = fixture.session(64)?;
        let mut workspace = ScanWorkspace::new(fixture.memory.clone());
        fixture.stores.application().seal();
        assert!(
            session
                .custody_visit_with_workspace(
                    namespace,
                    64,
                    &mut workspace,
                    ScanWorkspace::prepare,
                    |_, _, _, _| panic!("peer access failure must precede callback"),
                )
                .is_err()
        );
        assert_eq!(workspace.bytes, 0);
        session.close()?;
        drop(workspace);
        fixture.close().await?;
    }
    let fixture = Fixture::new(8 << 20).await?;
    fixture.write(b"secret")?;
    let mut session = fixture.session(64)?;
    let mut workspace = ScanWorkspace::new(fixture.memory.clone());
    let result = session.custody_visit_with_workspace(
        "payload",
        64,
        &mut workspace,
        ScanWorkspace::prepare,
        |workspace, _, _, value| {
            assert_eq!(value, b"secret");
            workspace.rows += 1;
            fixture
                .clock
                .advance(MAX_KEY_LEASE + Duration::from_nanos(1));
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(workspace.rows, 1);
    session.close()?;
    drop(workspace);
    fixture.close().await
}
