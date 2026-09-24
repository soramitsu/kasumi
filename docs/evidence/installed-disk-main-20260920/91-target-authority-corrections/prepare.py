from pathlib import Path
import difflib, hashlib, json, subprocess
root=Path('/Users/mtakemiya/dev/kasumi')
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
pkg=root/'target/installed-disk-validation/91-target-authority-corrections'
paths=['Cargo.lock','crates/kasumi-authority/Cargo.toml','crates/kasumi-authority/src/target_materialization_tests.rs','crates/kasumi-authority/src/target_serving_tests.rs']
base={p:(root/p).read_text() for p in paths}
proposed=dict(base)
p='crates/kasumi-authority/Cargo.toml'
proposed[p]=proposed[p].replace('[dev-dependencies]\n','[dev-dependencies]\nopenraft = { version = "=0.9.25", features = ["serde", "storage-v2"] }\n',1)
p='Cargo.lock'
start=proposed[p].index('name = "kasumi-authority"\n')
end=proposed[p].index('\n[[package]]',start)
block=proposed[p][start:end]
assert ' "openraft",' not in block
block=block.replace(' "ring",',' "openraft",\n "ring",',1)
proposed[p]=proposed[p][:start]+block+proposed[p][end:]
p='crates/kasumi-authority/src/target_materialization_tests.rs'
needle='async fn audit(\n'
helper='''/// Immediate phase closure can race the final durable application or its
/// acknowledgement. Completion still requires every actual owner to join;
/// preserve the exact access-fenced error rather than assuming a clean exit.
fn is_access_fenced_write(error: &openraft::StorageError<u64>) -> bool {
    if !matches!(error, openraft::StorageError::IO { .. }) {
        return false;
    }
    [
        "tenant is sealed: key-access lease unavailable or expired",
        "domain transaction committed; access expired before acknowledgment; outcome unknown",
    ]
    .into_iter()
    .any(|message| {
        // The adapter's terminal I/O cause is untyped. Compare the complete
        // Store/Write diagnostic, never an arbitrary matching substring.
        let expected = openraft::StorageError::<u64>::from_io_error(
            openraft::ErrorSubject::Store,
            openraft::ErrorVerb::Write,
            std::io::Error::other(message),
        );
        error.to_string() == expected.to_string()
    })
}

fn assert_target_close_outcomes(
    original: kasumi_types::drain::DrainResult,
    repeated: kasumi_types::drain::DrainResult,
) {
    use kasumi_types::drain::DrainCompletion;
    let (failure, repeated) = match (original, repeated) {
        (Ok(()), Ok(())) => return,
        (Err(failure), Err(repeated)) => (failure, repeated),
        outcomes => panic!("target drain changed its original outcome: {outcomes:?}"),
    };
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(repeated.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 1, "{failure:?}");
    assert_eq!(repeated.issues().len(), 1, "{repeated:?}");
    let issue = &failure.issues()[0];
    assert!(Arc::ptr_eq(issue, &repeated.issues()[0]));
    assert_eq!(issue.component(), "OpenRaft runtime");
    assert_eq!(issue.instance(), 0);
    let runtime = issue
        .error()
        .downcast_ref::<openraft::error::ShutdownError<u64, tokio::task::JoinError>>()
        .expect("original typed OpenRaft shutdown error missing");
    assert!(runtime.core().is_none(), "{runtime:?}");
    assert!(runtime.core_join_error().is_none(), "{runtime:?}");
    assert!(runtime.ticker().is_none(), "{runtime:?}");
    assert!(runtime.snapshot_builder().is_none(), "{runtime:?}");
    assert!(runtime.replications().is_empty(), "{runtime:?}");
    assert!(runtime.auxiliary().is_empty(), "{runtime:?}");
    assert!(runtime.incoming_snapshot().is_none(), "{runtime:?}");
    let storage = runtime
        .state_machine()
        .and_then(|worker| worker.storage_error())
        .expect("actual access-fenced state-machine error missing");
    assert!(is_access_fenced_write(storage), "{storage:?}");
    eprintln!("target owners drained with their original access-fenced outcome: {failure:?}");
}

#[test]
fn target_close_diagnostic_rejects_unrelated_storage_failures() {
    use openraft::{ErrorSubject, ErrorVerb, StorageError};
    let closed = "tenant is sealed: key-access lease unavailable or expired";
    let failure = |subject, verb, message: &str| {
        StorageError::<u64>::from_io_error(subject, verb, std::io::Error::other(message))
    };
    assert!(is_access_fenced_write(&failure(
        ErrorSubject::Store,
        ErrorVerb::Write,
        closed,
    )));
    assert!(!is_access_fenced_write(&failure(
        ErrorSubject::Store,
        ErrorVerb::Read,
        closed,
    )));
    assert!(!is_access_fenced_write(&failure(
        ErrorSubject::Vote,
        ErrorVerb::Write,
        closed,
    )));
    assert!(!is_access_fenced_write(&failure(
        ErrorSubject::Store,
        ErrorVerb::Write,
        "injected storage failure",
    )));
    assert!(!is_access_fenced_write(&failure(
        ErrorSubject::Store,
        ErrorVerb::Write,
        &format!("unrelated failure: {closed}"),
    )));
}

'''
assert proposed[p].count(needle)==1
proposed[p]=proposed[p].replace(needle,helper+needle,1)
old='''            t.owner.close().await.unwrap();
            drop(t.owner);
            drop(t.operation);
            t.scope.close();
            t.scope.drain().await;
'''
new='''            let original = t.owner.close().await;
            let repeated = t.owner.close().await;
            assert_target_close_outcomes(original, repeated);
            assert!(t.operation.invocation().gate().check().is_err());
            assert!(t.owner.database().raft_group().check_access().is_err());
            assert!(t.stores.application().check_access().is_err());
            assert!(t.stores.custody().store().check_access().is_err());
            drop(t.owner);
            drop(t.operation);
            t.scope.close();
            t.scope.drain().await;
            assert!(t.scope.is_idle());
'''
assert proposed[p].count(old)==1
proposed[p]=proposed[p].replace(old,new,1)
p='crates/kasumi-authority/src/target_serving_tests.rs'
old='''        self.owner.close().await.unwrap();
        drop(self.owner);
'''
new='''        let original = self.owner.close().await;
        let repeated = self.owner.close().await;
        assert_target_close_outcomes(original, repeated);
        assert!(self.owner.database().is_err());
        assert!(self.stores.application().check_access().is_err());
        assert!(self.stores.custody().store().check_access().is_err());
        drop(self.owner);
'''
assert proposed[p].count(old)==1
proposed[p]=proposed[p].replace(old,new,1)
old='''        database
            .raft_group()
            .raft()
            .add_learner(id, kasumi_raft::BasicNode::new("target-maintained"), false)
            .await
            .unwrap();
'''
new='''        // AddNodes deliberately preserves an existing node's address. This
        // fixture updates the same physical voter's operational metadata; it
        // neither admits a replacement owner nor changes the voter set.
        database
            .raft_group()
            .raft()
            .change_membership(
                openraft::ChangeMembers::SetNodes(BTreeMap::from([(
                    id,
                    kasumi_raft::BasicNode::new("target-maintained"),
                )])),
                true,
            )
            .await
            .unwrap();
'''
assert proposed[p].count(old)==1
proposed[p]=proposed[p].replace(old,new,1)
for group,values in [('base',base),('proposed',proposed)]:
 for path,content in values.items():
  dest=pkg/group/path
  dest.parent.mkdir(parents=True,exist_ok=True)
  dest.write_text(content)
patch=''.join(''.join(difflib.unified_diff(base[p].splitlines(True),proposed[p].splitlines(True),fromfile='a/'+p,tofile='b/'+p)) for p in paths)
(pkg/'corrections.patch').write_text(patch)
manifest={'status':'PREPARED_NOT_APPLIED_NOT_BUILT','workspace':str(root),'branch':'master','head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'patch_sha256':hashlib.sha256(patch.encode()).hexdigest(),'files':[{'path':p,'base_sha256':hashlib.sha256(base[p].encode()).hexdigest(),'proposed_sha256':hashlib.sha256(proposed[p].encode()).hexdigest()} for p in paths]}
(pkg/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
