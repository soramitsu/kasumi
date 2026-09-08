# Bounded coherent snapshot lease ownership

The manager exclusively owns full leased document/ID roots. It charges copied
metadata and retained versions, shares unchanged archived values and owns the
bounded values selected by in-flight pages. Capture, committed publication and
retention expiration share one lock. Expiration synchronously drops full roots
without changing committed writes; response fences report CursorExpired after
expiration, including responses already encoded. Blocking monitor work retains
its actual database and work registration until physical drain.

All eleven frozen gates pass on 5c0193f and again after integration of permanent
schema/retirement byte counters at c951fe9. The gates cover lease5, staged9,
clock2, response1, query32/types12, snapshot16, backup5, full history5,
replicated3 and actual native coherent pages1, plus strict workspace Clippy,
fixture-free server checks and formatting. Every gate retains its exact source,
lockfile, executable and log hashes. Initial test-only compiler failures are
retained without claiming a full frozen pre-fix source manifest.

These are bounded fixtures, including actual encrypted history backup/restore.
They do not prove the final 3 GiB tenant, production maintenance reservations,
resource pressure under sustained load or 24-hour HA endurance gates. The final
main branch adds recovery and signer changes after c951fe9 and requires its own
combined-source validation.
