# Combined native TLS, receipt and restart checks

Frozen source `61b5f0b09b8f0e96114b7a94e0b8216bb76f22ae` passed these
macOS ARM64 focused tests with actual encrypted storage and native TLS where
the named test uses it:

| Gate | Actual tests | Seconds |
| --- | ---: | ---: |
| Target shutdown ownership | 1 passed | 238.737 |
| Signer worker ownership | 6 passed | 4.141 |
| Native/MCP receipts | 3 passed | 4.427 |
| Rejected native/MCP durable receipt | 1 passed | 3.343 |
| Three-node TLS replication, restore and restart | 1 passed | 41.178 |

The next test, `api::tests::native_sdk_query_feed_schema_preserve_literal_values_and_admission`,
failed during fixture setup. Its parsed exact `serde_json::Number` rendered as
`1e+400`, while its assertion expected `1e400`. No SDK schema or document
operation had run. Successor `4e3a29d` corrects only that canonical spelling
expectation, retaining the exact integer, decimal, marker-object, schema,
mutation, pagination, feed and admission assertions.

The cohort remains failed and the later 11 gates did not run. All six owned
process groups drained and source, tree and lock hashes remained unchanged.
The macOS linker warned that the test executable's unwind section exceeded the
compact unwind encoding limit; this warning is retained without suppression.

[evidence.json](evidence.json) records actual commands, features, binary hashes,
original 900-second deadlines and process receipts. [preservation.json](preservation.json)
binds copied raw logs, source inventory, dispatcher and plan. Actual executables
were separately copied and verified before target reuse. The earlier Linux
`3a8d512` restart failure remains failed; a passing macOS successor does not
replace the required Linux or final-source gates. These results establish no
capacity, performance, endurance or complete release acceptance.
