from pathlib import Path
import hashlib,json,difflib,subprocess
root=Path.cwd(); out=root/'target/installed-disk-validation/database-construction'
guards=root/'target/installed-disk-validation/installed-memory-engine-guards/proposed'
files={}; before={}; layers={}
def read(rel):
    p=guards/rel
    if p.exists():
        layers[rel]='corrected guards efeca43aa014510d6b078c5562bc7271cb85683d5b0b158e8ccf295c5695ed86'
    else:
        p=root/rel; layers[rel]='actual source'
    before[rel]=p.read_text(); files[rel]=before[rel]
    return files[rel]
def put(rel,text): files[rel]=text
def rep(text,old,new,count=1):
    assert text.count(old)==count,(old[:120],text.count(old),count)
    return text.replace(old,new)
p='crates/kasumi-engine/src/service.rs';s=read(p)
s=rep(s,'#[path = "database_workers.rs"]\nmod database_workers;','#[path = "database_workers.rs"]\nmod database_workers;\n#[path = "database_construction.rs"]\npub(crate) mod construction;')
start=s.index('    /// Every database uses its security ledger\'s exact installed node governor.')
end=s.index('    fn new_inner(',start)
s=s[:start]+s[end:]
s=rep(s,'    fn new_inner(','    fn finish_construction(')
put(p,s)
new='crates/kasumi-engine/src/database_construction.rs';before[new]='';layers[new]='new file'
put(new,'''//! Checked identity and clock preparation before any Database Raft startup.
//! This owns construction inputs; retained startup children remain owned by
//! SnapshotBufferOwner. It is not a replacement for the runtime startup census.
use super::{Database, DatabaseClocks, SecurityAudit, TenantEngine};
use crate::admission::NodeAdmission;
use kasumi_raft::{RaftGroup, RaftGroupConfig, RaftTransport};
use kasumi_store::TenantStorageSet;
use std::sync::Arc;

pub(crate) struct DatabaseConstruction {
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    clocks: DatabaseClocks,
}

impl DatabaseConstruction {
    pub(crate) fn new(
        stores: Arc<TenantStorageSet>,
        audit: Arc<SecurityAudit>,
    ) -> anyhow::Result<Self> {
        let memory = audit.admission().memory();
        memory.require_store_memory(audit.store())?;
        memory.require_store_memory(stores.application())?;
        Ok(Self {
            stores,
            audit,
            clocks: DatabaseClocks::default(),
        })
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn with_fixture_clock(
        stores: Arc<TenantStorageSet>,
        audit: Arc<SecurityAudit>,
        clock: Arc<kasumi_clock::EpochClock>,
    ) -> anyhow::Result<Self> {
        let mut construction = Self::new(stores, audit)?;
        anyhow::ensure!(
            matches!(
                construction.stores.application().storage_access().purpose(),
                kasumi_store::StoragePurpose::LocalFixture
            ),
            "fixture clock requires the exact fixture application store"
        );
        clock.now_ms()?;
        construction.clocks = DatabaseClocks {
            elapsed: clock.elapsed_clock(),
            command: Arc::new(super::FixtureCommandClock(clock)),
        };
        Ok(construction)
    }

    pub(crate) fn stores(&self) -> &Arc<TenantStorageSet> {
        &self.stores
    }

    pub(crate) fn admission(&self) -> &Arc<NodeAdmission> {
        self.audit.admission()
    }

    pub(crate) async fn start_local(
        self,
        engine: Arc<TenantEngine>,
        node_id: u64,
        name: String,
    ) -> anyhow::Result<Arc<Database>> {
        let buffers = self.admission().snapshot_buffer_owner()?;
        let group = RaftGroup::local(
            node_id,
            name,
            self.stores.clone(),
            engine.clone(),
            buffers,
        )
        .await?;
        // No fallible operation or suspension follows the successful transfer
        // of the retained Raft startup outcome into this Database owner.
        Ok(self.finish(engine, group))
    }

    pub(crate) async fn start_replicated(
        self,
        engine: Arc<TenantEngine>,
        node_id: u64,
        name: String,
        transport: Arc<dyn RaftTransport>,
        config: RaftGroupConfig,
    ) -> anyhow::Result<Arc<Database>> {
        let buffers = self.admission().snapshot_buffer_owner()?;
        let group = RaftGroup::open(
            node_id,
            name,
            self.stores.clone(),
            engine.clone(),
            transport,
            config,
            buffers,
        )
        .await?;
        Ok(self.finish(engine, group))
    }

    fn finish(self, engine: Arc<TenantEngine>, group: RaftGroup) -> Arc<Database> {
        Database::finish_construction(
            engine,
            group,
            self.stores.application().clone(),
            self.audit,
            self.clocks,
        )
    }
}

#[cfg(test)]
#[path = "database_construction_tests.rs"]
mod tests;
''')
new='crates/kasumi-engine/src/database_construction_tests.rs';before[new]='';layers[new]='new file'
put(new,(out/'construction_tests.rs').read_text())
p='crates/kasumi-engine/src/bootstrap.rs';s=read(p)
s=rep(s,'use kasumi_raft::{BasicNode, Config, RaftGroup, RaftTransport};','use crate::service::construction::DatabaseConstruction;\nuse kasumi_raft::{BasicNode, Config, RaftTransport};')
# Replace direct memory checks with owned checked contexts at entry.
s=rep(s,'''    replica
        .admission
        .memory()
        .require_store_memory(targets.application())?;''','''    let construction = DatabaseConstruction::new(targets.clone(), security_audit.clone())?;''')
s=rep(s,'''    let group = RaftGroup::open(
        replica.node_id,
        format!("{}/{}", target.tenant(), bootstrap.incarnation),
        targets.clone(),
        engine.clone(),
        transport,
        kasumi_raft::RaftGroupConfig {
            raft: replica.raft,
            limits: kasumi_raft::RaftLimits::default(),
        },
        replica.admission.snapshot_buffer_owner()?,
    )
    .await?;
    let database = Database::new(engine, group, target, security_audit);''','''    let database = construction
        .start_replicated(
            engine,
            replica.node_id,
            format!("{}/{}", target.tenant(), bootstrap.incarnation),
            transport,
            kasumi_raft::RaftGroupConfig {
                raft: replica.raft,
                limits: kasumi_raft::RaftLimits::default(),
            },
        )
        .await?;''')
# Replicated constructor entry (the same guard appears in local helpers; replace in section).
a=s.index('async fn open_replicated_inner');b=s.index('/// Explicit first creation',a)
section=s[a:b]
section=rep(section,'''    security_audit
        .admission()
        .memory()
        .require_store_memory(stores.application())?;''','''    let construction = DatabaseConstruction::new(stores.clone(), security_audit.clone())?;''')
section=rep(section,'''    let group = RaftGroup::open(
        node_id,
        format!("{}/{}", store.tenant(), bootstrap.incarnation),
        stores.clone(),
        engine.clone(),
        transport,
        kasumi_raft::RaftGroupConfig {
            raft: config,
            limits: kasumi_raft::RaftLimits::default(),
        },
        security_audit.admission().snapshot_buffer_owner()?,
    )
    .await?;
    let database = Database::new(engine, group, store, security_audit);''','''    let database = construction
        .start_replicated(
            engine,
            node_id,
            format!("{}/{}", store.tenant(), bootstrap.incarnation),
            transport,
            kasumi_raft::RaftGroupConfig {
                raft: config,
                limits: kasumi_raft::RaftLimits::default(),
            },
        )
        .await?;''')
s=s[:a]+section+s[b:]
# Public local entry points construct before entering any bootstrap code.
s=rep(s,'''    open_local_inner(
        stores,
        initial_policy,
        initial_limits,
        security_audit,
        None,
        LocalRuntime::Production,
    )''','''    open_local_inner(
        DatabaseConstruction::new(stores, security_audit)?,
        initial_policy,
        initial_limits,
        None,
        LocalRuntime::Production,
    )''')
s=rep(s,'''    open_local_inner(
        stores,
        initial_policy,
        initial_limits,
        security_audit,
        Some(incarnation),
        LocalRuntime::Production,
    )''','''    open_local_inner(
        DatabaseConstruction::new(stores, security_audit)?,
        initial_policy,
        initial_limits,
        Some(incarnation),
        LocalRuntime::Production,
    )''')
a=s.index('pub async fn open_existing_local');b=s.index('/// Explicit genesis',a);sec=s[a:b]
sec=rep(sec,'''    security_audit
        .admission()
        .memory()
        .require_store_memory(stores.application())?;''','''    let construction = DatabaseConstruction::new(stores.clone(), security_audit)?;''')
sec=rep(sec,'''    start(
        stores,
        &bytes,
        LocalRuntime::Production,
        security_audit,
        Some(expected_incarnation),
    )''','''    start(
        construction,
        &bytes,
        LocalRuntime::Production,
        Some(expected_incarnation),
    )''');s=s[:a]+sec+s[b:]
s=rep(s,'''    clock.now_ms()?;
    open_local_inner(
        stores,
        initial_policy,
        initial_limits,
        security_audit,
        None,
        LocalRuntime::Fixture { clock },
    )''','''    let construction = DatabaseConstruction::with_fixture_clock(stores, security_audit, clock)?;
    open_local_inner(
        construction,
        initial_policy,
        initial_limits,
        None,
        LocalRuntime::FixtureDefault,
    )''')
s=rep(s,'''    #[cfg(any(test, feature = "test-utils"))]
    Fixture {
        clock: Arc<kasumi_clock::EpochClock>,
    },
''','')
s=rep(s,'''async fn open_local_inner(
    stores: Arc<TenantStorageSet>,
    initial_policy: Policy,
    initial_limits: Limits,
    security_audit: Arc<SecurityAudit>,
    incarnation: Option<uuid::Uuid>,
    runtime: LocalRuntime,
) -> anyhow::Result<Arc<Database>> {
    security_audit
        .admission()
        .memory()
        .require_store_memory(stores.application())?;
    let store = stores.application().clone();''','''async fn open_local_inner(
    construction: DatabaseConstruction,
    initial_policy: Policy,
    initial_limits: Limits,
    incarnation: Option<uuid::Uuid>,
    runtime: LocalRuntime,
) -> anyhow::Result<Arc<Database>> {
    let stores = construction.stores().clone();
    let store = stores.application().clone();''')
s=rep(s,'    start(stores, &bytes, runtime, security_audit, incarnation).await','    start(construction, &bytes, runtime, incarnation).await')
s=rep(s,'''async fn start(
    stores: Arc<TenantStorageSet>,
    bytes: &SnapshotImage,
    runtime: LocalRuntime,
    security_audit: Arc<SecurityAudit>,
    expected_incarnation: Option<uuid::Uuid>,
) -> anyhow::Result<Arc<Database>> {
    validate_bootstrap_control(&stores, bytes)?;''','''async fn start(
    construction: DatabaseConstruction,
    bytes: &SnapshotImage,
    runtime: LocalRuntime,
    expected_incarnation: Option<uuid::Uuid>,
) -> anyhow::Result<Arc<Database>> {
    let stores = construction.stores();
    validate_bootstrap_control(stores, bytes)?;''')
s=rep(s,'    start_prepared(stores, engine, runtime, security_audit).await','    start_prepared(construction, engine, runtime).await')
a=s.index('async fn start_prepared(');b=s.index('/// Exact independently authorized',a)
s=s[:a]+'''async fn start_prepared(
    construction: DatabaseConstruction,
    engine: Arc<TenantEngine>,
    runtime: LocalRuntime,
) -> anyhow::Result<Arc<Database>> {
    let store = construction.stores().application().clone();
    engine.install_storage_access(&store)?;
    let admission = construction.admission().clone();
    engine
        .verify_bootstrap_dependencies_owned(admission.clone())
        .await?;
    if matches!(runtime, LocalRuntime::Production) {
        engine.install_audit_maintenance(&admission)?;
    }
    let incarnation = engine.generation()?.state.incarnation.clone();
    construction
        .start_local(engine, 1, format!("{}/{incarnation}", store.tenant()))
        .await
}

'''+s[b:]
a=s.index('pub async fn restore_local(');sec=s[a:]
sec=rep(sec,'''    security_audit
        .admission()
        .memory()
        .require_store_memory(targets.application())?;''','''    let construction = DatabaseConstruction::new(targets.clone(), security_audit.clone())?;''')
sec=rep(sec,'''    let database = start_prepared(
        targets,
        restored.engine,
        LocalRuntime::Production,
        security_audit,
    )''','''    let database = start_prepared(construction, restored.engine, LocalRuntime::Production)''')
s=s[:a]+sec;put(p,s)
# Canonical fixture bootstrap propagates the checked construction object.
p='crates/kasumi-engine/src/bootstrap_fixtures.rs';s=read(p)
s=rep(s,'''    open_local_inner(
        stores,
        policy,
        limits,
        audit,
        None,''','''    open_local_inner(
        DatabaseConstruction::new(stores, audit)?,
        policy,
        limits,
        None,''')
s=rep(s,'''    open_local_inner(
        stores,
        policy,
        limits,
        audit,
        Some(incarnation),''','''    open_local_inner(
        DatabaseConstruction::new(stores, audit)?,
        policy,
        limits,
        Some(incarnation),''');put(p,s)
# Both target wrappers retain the checked inputs before their first child.
for filename,audit in [('bootstrap_target_quorum.rs','security_audit'),('bootstrap_target_serving.rs','audit')]:
 p='crates/kasumi-engine/src/'+filename;s=read(p)
 s=rep(s,'''    config
        .admission
        .memory()
        .require_store_memory(stores.application())?;''',f'''    let construction = DatabaseConstruction::new(stores.clone(), {audit}.clone())?;''')
 if filename=='bootstrap_target_quorum.rs':
  old='''        let group = RaftGroup::open(
            config.node_id,
            format!(
                "{}/{}",
                stores.application().tenant(),
                bootstrap.incarnation
            ),
            stores.clone(),
            engine.clone(),
            transport,
            kasumi_raft::RaftGroupConfig {
                raft: config.raft,
                limits: kasumi_raft::RaftLimits::default(),
            },
            config.admission.snapshot_buffer_owner()?,
        )
        .await?;
        let database = Database::new(engine, group, stores.application().clone(), security_audit);'''
  name='''format!(
                    "{}/{}",
                    stores.application().tenant(),
                    bootstrap.incarnation
                )'''
 else:
  old='''        let group = RaftGroup::open(
            config.node_id,
            format!("{}/{}", projection.tenant(), bootstrap.incarnation),
            stores.clone(),
            engine.clone(),
            transport,
            kasumi_raft::RaftGroupConfig {
                raft: config.raft,
                limits: kasumi_raft::RaftLimits::default(),
            },
            config.admission.snapshot_buffer_owner()?,
        )
        .await?;
        let database = Database::new(engine, group, stores.application().clone(), audit);'''
  name='format!("{}/{}", projection.tenant(), bootstrap.incarnation)'
 s=rep(s,old,f'''        let database = construction
            .start_replicated(
                engine,
                config.node_id,
                {name},
                transport,
                kasumi_raft::RaftGroupConfig {{
                    raft: config.raft,
                    limits: kasumi_raft::RaftLimits::default(),
                }},
            )
            .await?;''');put(p,s)
# Private fixtures keep their prepared engine and maintenance mode; the context
# now selects the actual audit facade's snapshot custody instead of a fake owner.
p='crates/kasumi-engine/src/audit_maintenance_service.rs';s=read(p)
s=rep(s,'''            let group = RaftGroup::local(
                1,
                format!("tenant/{incarnation}"),
                stores,
                engine.clone(),
                kasumi_raft::SnapshotBufferOwner::fixture(),
            )
            .await
            .unwrap();
            let database = Database::new(engine, group, store.clone(), audit.clone());''','''            let database = crate::service::construction::DatabaseConstruction::new(stores, audit.clone())
                .unwrap()
                .start_local(engine, 1, format!("tenant/{incarnation}"))
                .await
                .unwrap();''')
s=rep(s,'''        let group = RaftGroup::local(
            1,
            format!("tenant/{incarnation}"),
            stores,
            engine.clone(),
            kasumi_raft::SnapshotBufferOwner::fixture(),
        )
        .await
        .unwrap();
        let database = Database::new(engine.clone(), group.clone(), store, audit.clone());''','''        let database = crate::service::construction::DatabaseConstruction::new(stores, audit.clone())
            .unwrap()
            .start_local(engine.clone(), 1, format!("tenant/{incarnation}"))
            .await
            .unwrap();
        let group = database.raft_group().clone();''')
s=rep(s,'''        audit.shutdown().await.unwrap();
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), 0);''','''        audit.shutdown().await.unwrap();
        assert_eq!(
            crate::test_utils::reserved_payload_bytes(&admission),
            kasumi_raft::SnapshotBufferOwner::required_bytes(kasumi_raft::SNAPSHOT_BUFFER_SLOTS)
                .unwrap()
        );
        drop(group);
        drop(database);
        assert_eq!(crate::test_utils::reserved_payload_bytes(&admission), 0);''')
put(p,s)
p='crates/kasumi-engine/src/database_worker_outcome_tests.rs';s=read(p)
s=rep(s,'''        let group = RaftGroup::local(
            1,
            format!("{name}/{incarnation}"),
            stores,
            engine.clone(),
            kasumi_raft::SnapshotBufferOwner::fixture(),
        )
        .await?;
        let database = Database::new(engine, group, store, audit.clone());''','''        let database = construction::DatabaseConstruction::new(stores, audit.clone())?
            .start_local(engine, 1, format!("{name}/{incarnation}"))
            .await?;''');put(p,s)
p='crates/kasumi-engine/tests/admission.rs';s=read(p)
s=rep(s,'''use kasumi_engine::{
    Database, TenantEngine,
    admission::{AdmissionConfig, NodeAdmission},
};
use kasumi_raft::RaftGroup;''','''use kasumi_engine::admission::{AdmissionConfig, NodeAdmission};''')
a=s.index('    let engine = Arc::new(');b=s.index('    // Startup and audit use the same healthy facade.',a)
s=s[:a]+'''    let stores = kasumi_store::test_utils::initialize_custody_fixture(
        store,
        Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    let database = kasumi_engine::test_utils::open_fixture(
        stores,
        policy,
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    let group = database.raft_group().clone();
'''+s[b:];put(p,s)
# Render only the prepared copies. Parse/format through stdin, never real source.
for rel,source in list(files.items()):
 r=subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true'],input=source,text=True,capture_output=True)
 assert r.returncode==0,(rel,r.stderr)
 files[rel]=r.stdout
 p=out/'proposed'/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(r.stdout)
changes=[];patches=[]
for rel,newtext in files.items():
 original=before[rel]
 if original==newtext: continue
 patches.append(''.join(difflib.unified_diff(original.splitlines(True),newtext.splitlines(True),fromfile=('a/'+rel if original else '/dev/null'),tofile='b/'+rel)))
 changes.append({'path':rel,'baseline':layers[rel], 'before_sha256':hashlib.sha256(original.encode()).hexdigest() if original else None,'proposed_sha256':hashlib.sha256(newtext.encode()).hexdigest()})
patch=''.join(patches);(out/'construction.patch').write_text(patch)
manifest={'status':'TARGET_ONLY_UNCOMPILED','stack_after':['node-disk-memory revision 2 pending','installed-disk-core-adapter rebased after startup foundation pending','installed-memory-engine-guards efeca43aa014510d6b078c5562bc7271cb85683d5b0b158e8ccf295c5695ed86'],'patch_sha256':hashlib.sha256(patch.encode()).hexdigest(),'files':changes}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(manifest['patch_sha256'], len(changes))
