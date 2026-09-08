# Exact staged append resolution during archival

Source `3979ba5be4191f31c08238d3dc8eef47615848d8` passed the focused full cold
history backup/restore test in 308.23 seconds. The helper retains the original
staged chunk and resolves its exact identity after an ambiguous acknowledgement.
Strict engine history-target Clippy passed at that source. The manifest captures
the tested executable and raw failure/pass logs; copied-files.json also hashes
the subsequent strict-check log.

The earlier f926cc0 run failed on an unexpected status error whose exact code
was omitted by the assertion. Its cause remains unproven; a diagnostic-only
follow-up passed. This pass is not evidence that fault injection occurred, nor
is it a final-source Linux or 3 GiB capacity gate.
