# Kernel Stability & Execution Discipline

> SentinelCore Kernel Driver (`sentinel_km.sys`) — Engineering Reference  
> Version 1.0 · March 2026

---

## 1. Design Principles

The kernel driver is built under a strict **production-first stability model**. Every design decision assumes the driver is running on real endpoints with zero tolerance for system disruption.

| Principle                                       | Constraint                                                                 |
| ----------------------------------------------- | -------------------------------------------------------------------------- |
| No blocking in callback paths                   | Callbacks must return in bounded time                                      |
| No file I/O in kernel callbacks                 | `FltGetFileNameInformation` only on safe IRP paths                         |
| No recursive filter invocation                  | Protected process is explicitly excluded from filter decisions             |
| No user-mode dependency inside kernel execution | Kernel never waits for user-mode acknowledgment                            |
| Detection-only architecture                     | Driver collects and exports telemetry; all decisions are made in user-mode |

**The driver prioritizes system integrity over aggressive intervention.** When in doubt, the driver passes through — it will never deny a legitimate operation to prevent a false positive from degrading system stability.

---

## 2. IRQL Discipline

The driver enforces strict IRQL correctness at every execution boundary. All guarantees are coded explicitly via `PAGED_CODE()`, `#pragma alloc_text`, and SAL annotations.

### 2.1 Execution Context Map

| Routine                  | File               | Declared IRQL       | Enforcement                           |
| ------------------------ | ------------------ | ------------------- | ------------------------------------- |
| `DriverEntry`            | `driver.c`         | `PASSIVE_LEVEL`     | `#pragma alloc_text(INIT, ...)`       |
| `DriverUnload`           | `driver.c`         | `PASSIVE_LEVEL`     | `PAGED_CODE()`                        |
| `RegisterObCallbacks`    | `handle_protect.c` | `<= PASSIVE_LEVEL`  | `_IRQL_requires_max_(PASSIVE_LEVEL)`  |
| `PreOperationCallback`   | `handle_protect.c` | `<= APC_LEVEL`      | No paged access; no blocking          |
| `MiniFilterInit`         | `minifilter.c`     | `PASSIVE_LEVEL`     | `PAGED_CODE()`                        |
| `PreCreateCallback`      | `minifilter.c`     | `PASSIVE_LEVEL`     | `IRP_MJ_CREATE` guarantee             |
| `RingBufferPush`         | `ringbuffer.c`     | `<= DISPATCH_LEVEL` | `_IRQL_requires_max_(DISPATCH_LEVEL)` |
| `RingBufferDrain`        | `ringbuffer.c`     | `<= DISPATCH_LEVEL` | Called from IOCTL dispatch (PASSIVE)  |
| `RingBufferInit/Destroy` | `ringbuffer.c`     | `PASSIVE_LEVEL`     | `PAGED_CODE()` on Destroy             |
| `DispatchDeviceControl`  | `comms.c`          | `PASSIVE_LEVEL`     | `PAGED_CODE()`                        |

### 2.2 Guarantees

- No paged memory access at `IRQL >= DISPATCH_LEVEL`.
- No `Zw*` calls inside callback paths.
- No waiting primitives (`KeWaitForSingleObject`, `KeDelayExecutionThread`) anywhere in the driver.
- `ObRegisterCallbacks` pre-operation callback executes at `<= APC_LEVEL` — verified against WDK documentation.

---

## 3. Memory Management

### 3.1 Pool Allocation Policy

All kernel memory used in callback paths is allocated from **`NonPagedPoolNx`** (execute-disabled non-paged pool). This satisfies both the IRQL requirement (accessible at any level) and modern security requirements (no executable data pool).

```c
/* Pool tags — readable backwards in poolmon.exe */
#define SNTL_TAG_GENERAL  'ltnS'   /* General driver allocations  */
#define SNTL_TAG_EVENT    'vEtS'   /* Ring buffer event nodes      */
```

All allocations use `ExAllocatePool2(POOL_FLAG_NON_PAGED, ...)` — the modern, secure API introduced in Windows 10 2004 that defaults to `NonPagedPoolNx` and zero-initializes memory.

### 3.2 Ring Buffer Memory Model

The telemetry ring buffer uses a **pre-bounded doubly-linked list** with a hard capacity of 4,096 nodes:

```
Max NonPagedPool usage:
  4,096 nodes × sizeof(SENTINEL_EVENT)
= 4,096 × ~316 bytes
≈ 1.2 MB maximum NonPagedPool consumption
```

When the buffer reaches capacity, the **oldest event is evicted** before inserting the new one. This guarantees a fixed upper bound on memory usage regardless of event rate — no unbounded growth is possible.

### 3.3 Unload Cleanup Discipline

During `DriverUnload`, teardown proceeds in **exact reverse initialization order**:

```
DriverEntry Init Order:       DriverUnload Teardown Order:
  1. Ring Buffer          →     4. Mini-filter
  2. Communication Device →     3. ObCallbacks
  3. ObCallbacks          →     2. Protected process reference
  4. Mini-filter          →     1. Communication device
                                0. Ring buffer
```

After teardown:

- All `SENTINEL_EVENT` nodes freed via `ExFreePoolWithTag(..., SNTL_TAG_EVENT)`.
- All `PEPROCESS` references released via `ObDereferenceObject`.
- All symbolic links deleted before device object deletion.
- No outstanding object references remain.

---

## 4. Synchronization Strategy

### 4.1 Locking Design

The driver uses **two distinct synchronization primitives** with clearly separated roles:

| Primitive                               | Protects                                         | Used In                                                  |
| --------------------------------------- | ------------------------------------------------ | -------------------------------------------------------- |
| `EX_PUSH_LOCK` (`ProtectedProcessLock`) | `ProtectedProcess` + `ProtectedPid` pointer swap | ObCallbacks, IOCTL dispatch, DriverUnload                |
| `KSPIN_LOCK` (`RingBuffer.Lock`)        | Ring buffer `LIST_ENTRY` + count fields          | `RingBufferPush`, `RingBufferDrain`, `RingBufferDestroy` |

`EX_PUSH_LOCK` is used for the protected process pointer because:

- It supports shared (read) + exclusive (write) semantics.
- It is acquired in shared mode in the hot `PreOperationCallback` path.
- Multiple concurrent callbacks can read without contention.

`KSPIN_LOCK` is used for the ring buffer because:

- It must be held at `DISPATCH_LEVEL` when called from `RingBufferPush`.
- It provides the necessary IRQL elevation guarantee.

### 4.2 Deadlock Avoidance

The driver's lock ordering is strictly enforced. There is **exactly one locking level** per subsystem and they never nest:

```
Rule 1: ProtectedProcessLock is never held while acquiring RingBuffer.Lock.
Rule 2: RingBuffer.Lock is never held while calling any non-trivial function.
Rule 3: No lock is held when calling FltGetFileNameInformation.
Rule 4: No lock is held when calling ExAllocatePool2 (can fail, must not deadlock).
```

Circular dependency analysis:

```
ObCallback path:   [ProtectedProcessLock(Shared)] → [RingBuffer.Lock] → Release both
MiniFilter path:   No lock held during FltGetFileNameInformation
                   → [ProtectedProcessLock(Shared)] → [RingBuffer.Lock] → Release both
IOCTL path:        [ProtectedProcessLock(Exclusive)] — no ring buffer lock needed
                   OR  [RingBuffer.Lock] — no process lock needed
```

No circular dependency exists between these three paths.

---

## 5. Callback Lifecycle Safety

### 5.1 `ObRegisterCallbacks` Lifecycle

```
DriverEntry                        DriverUnload
    │                                  │
    ▼                                  ▼
ObRegisterCallbacks()         ObUnRegisterCallbacks()
    │                                  │
    ▼                                  ▼
g_State.ObRegistrationHandle    g_State.ObRegistrationHandle = NULL
    (stored, non-NULL)              (cleared after unregister)
```

`ObUnRegisterCallbacks` is called **before** freeing any state the callback might dereference. The WDK guarantees that after `ObUnRegisterCallbacks` returns, no new callback invocations will occur. This prevents any use-after-free from a late callback.

### 5.2 `FltRegisterFilter` Lifecycle

```
DriverEntry                        DriverUnload
    │                                  │
    ▼                                  ▼
FltRegisterFilter()              FltUnregisterFilter()
FltStartFiltering()                  │
    │                                  ▼
g_State.Filter (stored)          g_State.Filter = NULL
```

`FltUnregisterFilter` is called first in the mini-filter teardown. The filter manager drains in-flight callbacks before returning. The protected process `PEPROCESS` reference is released only **after** the mini-filter is unregistered, ensuring `SentinelGetProtectedProcessReferenced` cannot return a dangling pointer.

### 5.3 Protected Process Reference Safety

The `SentinelGetProtectedProcessReferenced` function acquires a shared `EX_PUSH_LOCK` and bumps the `PEPROCESS` reference count before returning. **All callers must call `ObDereferenceObject` when done.** This pattern is used in both `PreOperationCallback` and `PreCreateCallback`.

---

## 6. Detection-Only Safety Model

`sentinel_km.sys` does **not**:

- Hard-deny handle creation (returns `OB_PREOP_SUCCESS` always, after masking).
- Terminate or suspend processes.
- Inject code or modify process memory.
- Perform enforcement decisions.

It **does**:

- Strip dangerous access rights from handle requests (`PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`, `PROCESS_DUP_HANDLE`).
- Deny write/delete file I/O on protected binaries.
- Export telemetry events to user-mode via ring buffer.

This architecture eliminates:

- Risk of false-positive enforcement causing service disruption.
- Kernel crashes from incorrect blocking semantics.
- User regression from overly aggressive access control.

All detection logic, behavioral correlation, and alerting runs in memory-safe Rust user-mode code where a crash is contained and recoverable.

---

## 7. Performance Considerations

### 7.1 Hot Path Complexity

| Path                   | Complexity     | Notes                                                         |
| ---------------------- | -------------- | ------------------------------------------------------------- |
| `PreOperationCallback` | O(1)           | Shared push-lock acquire, pointer compare, optional ring push |
| `PreCreateCallback`    | O(k)           | k = number of protected filenames (k=3, constant)             |
| `RingBufferPush`       | O(1) amortized | Spinlock + list insert + optional evict                       |
| `RingBufferDrain`      | O(n)           | n = number of events drained per IOCTL call                   |

### 7.2 Allocation Avoidance

`RingBufferPush` allocates one `SENTINEL_EVENT` node via `ExAllocatePool2`. On allocation failure, the event is **silently dropped** — the driver never panics on memory pressure:

```c
node = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SENTINEL_EVENT), SNTL_TAG_EVENT);
if (node == NULL) {
    return; /* Drop silently — never crash on allocation failure */
}
```

No allocation occurs in `PreOperationCallback` on the fast path (when no protection is active, the function returns immediately without touching the ring buffer).

### 7.3 String Operations

`RtlStringCchCopyW` is used for all string operations in callback paths — bounded, no overflow possible. No `sprintf`, `swprintf`, or unbounded string routines appear anywhere in the driver.

---

## 8. Static Analysis & Verification

The driver is verified to be clean under the following tools before any deployment:

| Tool                             | What It Checks                                          |
| -------------------------------- | ------------------------------------------------------- |
| **MSBuild /W4 /WX**              | Zero warnings at Warning Level 4, warnings-as-errors    |
| **Static Driver Verifier (SDV)** | Lock order, IRQL violations, pool tags, callback safety |
| **Driver Verifier (dynamic)**    | Pool tracking, force-IRQL checking, I/O verification    |
| **`!analyze -v`**                | Post-crash BSOD analysis on any test failure            |
| **SAL annotations**              | All pointer, IRQL, and buffer contracts machine-checked |

`PAGED_CODE()` assertions appear in every pageable function. Any IRQL violation will fail immediately in a checked build rather than silently corrupting memory.
