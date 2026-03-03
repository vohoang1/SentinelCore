# Changelog

## 2026-03-03 - Milestone A1: ETW Correlation Layer (Kernel + User Boundary)
- Added `EventKind::KernelTelemetry` and kernel telemetry schema in normalized event model.
- Added ETW correlation state to keep per-PID timeline (`process` + `image load`) for join logic.
- Added kernel telemetry listener thread that continuously drains driver telemetry and pushes to pipeline.
- Added correlation join in user-mode: kernel event now carries ETW context for source/target PID in a bounded time window.
- Added image-load provider wiring in ETW listener and timeline recording hooks.
- Fixed shutdown token mismatch between driver token and user-mode IOCTL client.
