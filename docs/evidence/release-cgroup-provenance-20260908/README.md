# Release resource provenance

`fbae79f` passes all 20 Python release-tool tests and YAML/bash syntax checks.
An actual restricted Linux ARM64 container reports its 15 GiB memory ceiling,
zero swap ceiling and available cgroup memory counters using the exact helper.
This was an idle observation, not a pressure or OOM test.

The functional runner now hashes before/after cgroup observations for each gate,
including failed child processes; packaging requires unchanged resource files.
The workflow preflights inside its actual container and retains created/terminal
Docker records while stopping only its owned container on exit. A child OOM kill
can occur without Docker marking the whole container OOM-killed.

The failed initial packaging fixture run remains here. These focused checks do
not claim execution of the hosted workflow or completion of release gates.
