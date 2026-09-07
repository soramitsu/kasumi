# Interrupted snapshot custody gate

This run was deliberately interrupted after an independent reproduction confirmed
that equivalent persistent map state can serialize differently after reopening.
The then-current same-position byte equality check was therefore unsound. The
receipt records 84 tests completed successfully before SIGINT, no observed failed
test and 141 unchanged native inputs. It is incomplete evidence, not a full pass.

The subsequent correction preserves each image's exact digest while comparing
complete validated custody identity and membership at the same applied position.
The corrected tests and final gate are recorded separately.
