# Crash fixture private installation

Target-only correction for the observed run88 contracts failure. The subprocess already acknowledged its real durable write and was killed/drained, but the parent next censused the same directory containing ack.json written by the test harness with ordinary file permissions. The production census correctly rejects that nonprivate file.

The test now creates an explicit 0700 persistent installation child before spawning the actual worker. Both worker and parent use its exact node.redb path; acknowledgment files remain in the outer test harness directory. This does not repair production permissions or bypass census. The original SIGKILL, 20-second acknowledgement deadline, write/receipt/bootstrap assertions and workloads remain unchanged. No actual source edit or behavioral test yet. rustfmt stdin and git apply --check passed.
