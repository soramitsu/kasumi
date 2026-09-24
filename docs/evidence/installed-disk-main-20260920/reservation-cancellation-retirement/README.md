# Cancellation charge retirement prerequisite

Target-only correction of the existing Reservation drop order identified during independent snapshot-owner review. No actual source edit, build or behavioral check. The charge owns a possible final QueryCancellation Arc whose concrete private state consists only of atomic fields (query/cancellation.rs). It has no destructor callback, allocation or admission lock acquisition. Dropping it under the core state mutex retires that existing backing before byte/operation/slot credits can be reused. This does not bound external token clones or solve the proposed snapshot Owner Arc tail.

The existing admission/core/workspace cohort remains required after application. Snapshot foundation itself remains unapplied pending complete final-owner backing retirement and the completed-failure census correction. No capacity or policy changes.
