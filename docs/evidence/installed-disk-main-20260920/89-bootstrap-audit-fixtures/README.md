# Two gate89 fixture corrections

Status: target only, uncompiled and unapplied. No workload, quota, timeout, canonical decoder or production owner behavior changes. The original terminal failed log remains unchanged and is hashed in manifest.json.

Gate89 ended with 210 passed, five failed, one ignored, one filtered test. This package addresses exactly two of those failures:

- `bootstrap::fixtures::tests::production_bootstrap_installs_shared_pool_for_application_and_control` failed only its final total-charge assertion, reporting 30,029,166 against 678,536. The 29,350,630 difference is the one persistent and one scratch installation's eight metadata leases. The earlier exact application/control maintenance and three snapshot-owner charge delta passed. The test now derives the real metadata plan before installation, asserts it before opening stores, and requires final total equal to bookkeeping plus exactly that retained metadata. It still detects any surviving operation or maintenance charge.
- `state::tenant_audit::tests::uncertain_preparation_reopens_the_same_encrypted_object_after_restart` passed the actual reopen, identical pending encrypted command, application and matching archive-head assertions, then failed a final directory enumeration with NotFound. Its fixture explicitly installs the remote test archive under `persistent/external`; the assertion still used the old root-level `external`. It now enumerates `store.durable_directory()/external`, which names that actual archive beside the reopened node file, and still requires exactly one object.

The independently reviewed retention correction remains a separate frozen package at `../89-audit-metadata-fixture/fixture.patch`, SHA9f31ad09ae51e14689cef4820f7b061ffc5423fd2603fe08220dc28e249a36a5. Gate89 confirmed its final expected-zero assertion: actual retained metadata was exactly 29,350,630. Its preserved original manifest predates that terminal attribution.

Validation performed here: rustfmt through stdin for only proposed copies and git apply --check. No compiler, test, source edit, branch or checkout action occurred.
