# Copyable private page-list range key

Target-only follow-up stacked after redb-page-list-prerequisites/prerequisites.patch (de8383c9c041c8dfd54ea8a7c0563de81dc8f46c86b0d95b65ffc2a9e1a688b8). The original package is unchanged.

Independent review found that validation consumes RangeBounds values before extraction reuses the same range keys; test insert/get calls also pass the key by value. TransactionIdWithPagination has exactly two u64 fields and previously derived only Debug. Derive Clone and Copy so these private encoded identity values may be reused without allocation or changed semantics. This does not change bytes, key ordering, counts, public API, or transaction behavior.

The one-line patch passes git apply --check against the exact target-only prerequisite source. No Cargo, rustc, test execution or actual source edits occurred. Compilation/runtime qualification remains root-owned.
