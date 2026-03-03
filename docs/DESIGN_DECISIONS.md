# Design Decisions

## 2026-03-03 - A1 ETW Correlation Layer

### Decision
Correlate kernel telemetry with ETW timeline in user-mode instead of expanding callback logic in kernel.

### Why
- Keeps Ob/MiniFilter callbacks cost-aware and simple.
- Avoids higher callback latency and lock contention in kernel.
- Preserves safety boundary: kernel emits minimal telemetry, user-mode enriches context.

### Implementation
- Kernel telemetry is normalized into `EventKind::KernelTelemetry`.
- ETW process and image-load events update a bounded PID timeline cache.
- Each kernel event is enriched with ETW correlation snapshot for both source PID and target PID.
- Correlation window is fixed (`30s`) and cache is periodically pruned.

### Tradeoffs
- Correlation is best-effort: missing ETW events produce partial context.
- Adds user-mode memory overhead for PID timeline state.

### Follow-up
- Next milestone replaces kernel linked-list telemetry queue with fixed-size lock-free ring buffer.
