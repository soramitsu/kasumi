# Unsuccessful debugger diagnosis of the retained stack overflow

The exact preserved failing server executable from `5233e96` was submitted to
the local LLDB without changing the default test-thread stack or test deadline.
LLDB remained at its launch command until the separate 90-second diagnostic
deadline. No target test result or backtrace was obtained. This is unsuccessful
diagnostic evidence and cannot turn the failed functional gate into a pass.

The LLDB process group was terminated and drained. LLDB had also created its
own `debugserver` in a separate session; the exact observed PID and command were
verified, terminated, and rechecked absent. Both cleanup records are retained
in `evidence.json`. The original binary hash and frozen source remained unchanged.

Source inspection found that nested preparation wrappers kept large futures
inline in each async state machine. The successor boxes preparation before
constructing its returned future, adds a bounded-future regression, and must
rerun the complete original ownership cohort under the original deadlines.
This diagnosis does not by itself establish that the correction resolves the
actual Control genesis failure.
