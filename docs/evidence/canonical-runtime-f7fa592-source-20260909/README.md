# Canonical runtime fixture source checkpoint

The frozen [coverage map](coverage-map.md) describes source f7fa592 and explicitly
records unrun compiler/runtime gates, planned-only scope, fixture signer ownership,
separate outer target restart, and the missing production dormant-tenant enrollment
path. The [erratum](erratum.md) retracts its mistaken claim that initialize_catalogs
was absent from that branch: the fresh-only API was already present. Both source
review artifacts are preserved byte-for-byte; neither is runtime evidence.

Root combined the fixture with canonical management 524d752/8f081a0, existing
storage ownership and cancelled-drain correction 63abded as source 7c43d67.
The frozen 7a21995 compiler/store plan excludes this later management/fixture
integration. All actual coordinator, shutdown and final release checks remain
open. No comparison table entry means the corresponding assertion passed.
