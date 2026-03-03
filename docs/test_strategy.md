# SentinelCore — Test & Validation Strategy

> Version 1.0 · March 2026  
> Classification: Internal — Engineering Reference

---

## 1. Objective

This document outlines the systematic testing methodology used to validate the reliability, performance, and security of the SentinelCore EDR pipeline. The testing strategy is divided into four distinct phases: Unit Validation, Kernel Stability, Telemetry Integrity, and Performance Profiling.

---

## 2. Unit Validation (User-Mode)

Unit testing focuses on the memory-safe Rust user-mode components. Each module is tested in isolation using the standard `cargo test` framework.

### 2.1 Detection Engine

- **Signature Matching:** Verify that known malicious command lines match exact YAML rules without regex catastrophic backtracking.
- **State Machine Transitions:** Inject mock `CreateProcess(SUSPENDED)` followed by `NtUnmapViewOfSection` into the Hollowing Detector and verify transition to Stage 2.
- **Temporal Windows:** Insert events with manipulated timestamps to ensure the 5-second correlation window correctly expires.
- **TTL Eviction:** Spawn a mock DashMap with 10,000 entries and trigger the TTL sweeper thread; verify memory is reclaimed.

### 2.2 Forensic Storage

- **Hashchain Integrity:** Write 1,000 mock events, truncate the last 10 bytes of the SQLite WAL file, and run the `verify` module. The system MUST identify the exact block where corruption occurred.
- **Crash Recovery:** Send `SIGKILL` to `sentinelcore.exe` during an active SQLite transaction. Restart the process and verify no database corruption using `PRAGMA integrity_check`.

### 2.3 Cloud Communcations

- **Backpressure Simulation:** Spin up a mock TLS server that accepts connections but reads at 1 byte per second. Flood the Uploader with events and verify that the Spooler correctly redirects to disk without expanding RAM beyond 50MB.
- **Identity Verification:** Ensure the Ed25519 payload generated matches the expected standard signature format.

---

## 3. Kernel Stability Validation (sentinel_km.sys)

Kernel testing is performed on a dedicated Windows 11 VM with **Driver Verifier** enabled.

### 3.1 Static Verification

Before any test ring deployment:

- `MSBuild /W4 /WX`: Zero warnings allowed.
- Static Driver Verifier (SDV): Zero defects related to lock ordering, IRQL levels, and pool tags.

### 3.2 Dynamic Stress Testing

- **Configuration:** Driver Verifier enabled with standard settings + I/O Verification + Pool Tracking + Force IRQL Checking.
- **Handle Abuse Gen:** A test script spawns 1,000 threads simultaneously attempting to call `OpenProcess(PROCESS_ALL_ACCESS)` against `sentinelcore.exe`.
  - _Expected:_ Driver responds with stripped masks or denies. System does not hang. Pool allocation `SntI` does not leak.
- **File Deletion Gen:** A test script recursively attempts `del /F /S /Q` on the agent installation directory.
  - _Expected:_ Only unprotected files are deleted. No BSOD on rapid IRP_MJ_CREATE storms.
- **Unauthorized Unload:** Attempt `sc stop sentinel_km` from a non-admin prompt, then an admin prompt without the IOCTL token.
  - _Expected:_ Denied or logged appropriately. System remains stable.

---

## 4. Telemetry Integrity Validation

This phase validates the end-to-end event flow from the Windows Kernel to the SQLite backend.

### 4.1 ETW Loss Prevention

- **High-Volume Load:** Compile a C++ program that forks 100,000 short-lived processes in 10 seconds.
- **Validation:** Compare the count of `ProcessStart` events in SQLite against the OS-reported count from PerfMon.
- **Target:** < 0.01% event loss across the pipeline.

### 4.2 Ring Buffer Drain

- **Latency Check:** Trigger 5,000 handle strips via the test harness.
- **Validation:** The user-mode client must pull all 5,000 events via synchronous `IOCTL_READ_TELEMETRY` calls without dropping any due to the kernel 4,096 hard cap. The read interval must be tuned to drain faster than the generation rate.

---

## 5. Performance Considerations

SentinelCore is designed to operate invisibly on the endpoint. Strict performance budgets are enforced.

### 5.1 CPU Overhead

- **Idle State:** < 0.5% CPU utilization (no active attacks, standard background OS noise).
- **Active Attack (High Load):** < 5% CPU utilization when processing rapid injection sequences.
- _Measurement:_ `Process Explorer` / PerfMon over a 24-hour baseline.

### 5.2 Latency Budgets

- **Kernel PreCreateCallback:** < 10μs per intercepted file operation.
- **Kernel PreOperationCallback:** < 5μs per intercepted handle request.
- **User-Mode Detection Pipeline:** < 5ms from ETW callback to alert generation (99th percentile).

### 5.3 Memory Envelope

- **Kernel NonPagedPool:** Capped absolutely at ~1.2MB (4096 Ring Buffer nodes).
- **User-Mode RAM (Working Set):** < 150MB sustained.
  - Dictated by bounded channels (`10,000` cap) and temporal event eviction.
  - If memory exceeds 200MB, the Overload Monitor initiates targeted event shedding.
