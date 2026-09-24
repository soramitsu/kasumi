# Gate142 compile correction

Target-only two-file correction stacked after the frozen canonical f2103f19 patch. No actual source, Cargo or native execution. Target rustfmt and apply-check pass; compiler qualification belongs to the root's successor gate. The complete failed142 log/result remain unchanged.

The original transformation was too broad in two places. Its replacement of a transaction argument by the system dirty AtomicBool also reached unrelated user TableNamespace methods; its removal of the obsolete system-free helper tail also removed the following independent stats/debug methods. This correction restores the entire TableNamespace block byte-for-byte from the pre-format4 base, including savepoint-aware user allocation tracking and all rename/delete signatures. SystemNamespace keeps the narrowly required AtomicBool borrow. The public WriteTransaction::stats method and its current-tree print_debug companion are restored byte-for-byte from that base; neither decodes obsolete SYSTEM records.

The new page-list tests import ReadableDatabase once at module scope; the redundant local ReadableTable import is removed. Assertions, physical workloads and fault custody remain intact.

The source-bound public-method inventory compares lexical public/pub(crate) fn name multisets. After restoration the only removed name is PageListKind::capacity, deliberately removed together with that obsolete format distinction; the only new name is data_reclaim_backlog_after_batch. This audit is narrower than a complete Rust symbol/signature audit and is not presented as compilation.
