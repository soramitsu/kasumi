# Offline upstream dependency preparation failure

The exact full upstream redb overlay bdde7978ddac88db4851cbf0c1f77f75f5778b47
could not resolve either verification graph from the local offline cache. The
root workspace lacks ctrlc, required by its retained benchmark member; the fuzz
workspace lacks libfuzzer-sys. Both actual Cargo metadata commands exited101.
No compiler ran, no target directory or lockfile was created, and both process
groups80658/80672 drained. The124 tracked source files and pinned process helper
stayed unchanged. These preparation failures do not test prototype behavior.

Network-enabled dependency preparation is required before freezing the two
verification locks and preparing the isolated offline upstream test harness.
The benchmark member and fuzz dependency are not removed to bypass resolution.
Raw logs, dispatcher and evidence are retained with byte-exact hashes.
