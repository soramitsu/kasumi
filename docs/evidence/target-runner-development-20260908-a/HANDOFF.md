# Target runner development handoff

Status: unfinished, uncommitted development; not a release or acceptance gate. The original owner is paused by an account usage limit. Native production task 01a07e1c-e2da-72e2-8c35-86968060bdff may compose a guarded copy of this source onto its production-v1 work. Preserve this source and raw diagnostics. No new tests were run during this capture.

Source base: d9ef813fe13723e9020d53cae1a91265c6b88ae3. It does not include later15f schema activation admission, so that must be reconciled explicitly. Exact source hashes/modes and original status are preserved. Diagnostic files contain both failures and later narrower passes; historical passing logs are not a full test of this captured final source.

Latest focused raw diagnostics include kasumi-target-local-confirmation-test-a.log and kasumi-target-serving-runtime-clippy-b.log. progress-history.md records the actual encrypted materialization, initialization, completion, activation, projection, local follower confirmation and serving-reopen tests, with explicit local/signed-fixture versus authenticated composed boundaries. Its older original5174 ownership comments are historical; the new native production task has independent user authorization.

Required work still includes actual composed pinned TLS Control and issuer quorums plus three target peers, metadata-only stop without source/application keys, authoritative post-expiry inspection, actual runtime serving promotion/restart and registration failure/shutdown/drain tests; full merged source-bound workspace correctness/strict checks remain outstanding. No native target-runner final commit exists. Earlier runner draft is historical design context only; inspect implemented code and latest progress before continuing.
