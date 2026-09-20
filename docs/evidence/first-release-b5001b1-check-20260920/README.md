# Frozen MCP and ownership successor: assertion failures

Native macOS ARM64 / Rust 1.97.1 ran clean source `b5001b1` against the retained
36-gate / 155-mandatory-case plan. Workspace all-targets/features compilation,
formatting, and the new engine owned-response-fence regression passed. The
fourth gate ran ten MCP tests: three existing cases passed and seven new cases
failed. The remaining 32 gates were not dispatched.

All seven failures compare lower-case test expectations against the API's
existing upper-case ErrorCode serialization. Observed values were UNAUTHORIZED,
CONFLICT, UNKNOWN_OUTCOME, RESOURCE_EXHAUSTED and UNAVAILABLE at the expected
fencing/error paths. The correction updates assertions, preserving production
serialization. Later assertions in each failed case remain unverified until
the corrected frozen successor runs. This attempt does not qualify MCP or the
previously repaired ownership fixtures.

Every dispatched process group drained without survivors or cleanup errors,
and source comparison remained unchanged. Raw files were copied unchanged from
`/Users/mtakemiya/dev/kasumi-release-evidence/20260920-b5001b1-ownership-mcp`;
`copied-files.json` binds their exact bytes. The two preserved test executables
remain in that external directory and their hashes were independently rechecked
in `summary.json`. The plan retains every original gate/case/deadline and adds
focused response-fence coverage. This is failed scoped evidence, not release
acceptance, a full workspace test run or strict workspace lint.

The added plan also misnames the three existing cases as `mcp::tests::*`.
Their actual source/test identities are `mcp::response_tests::*`, as shown in
the retained log. The successor must correct those identifiers while retaining
all three mandatory cases; the original plan bytes remain unchanged here.
