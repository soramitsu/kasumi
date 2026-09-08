# Linux reference VM memory expansion

After the failed d403c55 functional run became terminal and Docker reported no running containers, the owned kasumi-production-arm64 VM was stopped, expanded from8GiB to16GiB, and restarted. The same200GiB filesystem and all previous source/target/evidence directories remain. Before/after configuration, actual guest memory, free disk and operation log are retained. This provisioning change is not a passing functional or capacity gate.
