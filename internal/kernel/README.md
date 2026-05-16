# Kernel

The kernel is Plystra's minimal trusted substrate. It owns configuration, lifecycle orchestration, service registration, route registration, migration registration metadata, bootstrap events, and readiness.

It does not own complete domain semantics for identity, resource registry, authorization, audit, or admin control-plane behavior. Those capabilities are built-in privileged modules under `internal/system/*` and are wired through `internal/kernel/contracts`.

System capabilities are compiled into the main server for this release. They are not business plugins, not marketplace-installed, and not hot-swappable at runtime.
