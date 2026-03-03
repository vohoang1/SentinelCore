# SentinelCore — Threat Model

> Version 1.0 · March 2026  
> Classification: Internal — Engineering Reference

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Protected Assets](#2-protected-assets)
3. [Adversary Profile](#3-adversary-profile)
4. [Threat Catalog](#4-threat-catalog)
   - [T1 — Credential Access via LSASS](#t1--credential-access-via-lsass)
   - [T2 — Classic Remote Thread Injection](#t2--classic-remote-thread-injection)
   - [T3 — Process Hollowing](#t3--process-hollowing)
   - [T4 — RWX Memory Abuse](#t4--rwx-memory-abuse)
   - [T5 — APC Injection](#t5--apc-injection)
   - [T6 — Handle Abuse & Privilege Escalation](#t6--handle-abuse--privilege-escalation)
   - [T7 — Service-Based Privilege Escalation](#t7--service-based-privilege-escalation)
   - [T8 — EDR Tampering & Evasion](#t8--edr-tampering--evasion)
   - [T9 — Binary Replacement & Masquerading](#t9--binary-replacement--masquerading)
5. [Attack Chain Analysis](#5-attack-chain-analysis)
6. [Detection Coverage Matrix](#6-detection-coverage-matrix)
7. [Assumptions & Limitations](#7-assumptions--limitations)

---

## 1. Executive Summary

SentinelCore is designed to detect **post-exploitation activity** — the phase of an intrusion where an attacker has already gained initial access to a Windows endpoint and is attempting to:

- **Escalate privileges** (credential theft, token manipulation)
- **Move laterally** (process injection, remote service creation)
- **Maintain persistence** (service installation, binary replacement)
- **Neutralize defenses** (EDR tampering, ETW session disruption)

The detection philosophy is **behavioral correlation over single-event heuristics**. Rather than alerting on individual API calls (which produce excessive false positives), SentinelCore correlates sequences of events within bounded temporal windows to identify attack chains with high confidence.

The kernel driver (`sentinel_km.sys`) does **not** perform detection. Its sole purpose is **enforcement**: protecting the agent process from termination and its binaries from modification. All detection logic executes in memory-safe user-mode Rust code.

---

## 2. Protected Assets

| Asset                      | Value                                                 | Protection Layer                           |
| -------------------------- | ----------------------------------------------------- | ------------------------------------------ |
| `lsass.exe` credentials    | Domain/local passwords, Kerberos tickets, NTLM hashes | Detection: handle monitoring + correlation |
| Trusted process integrity  | Legitimate processes must not be hijacked             | Detection: injection pattern matching      |
| SentinelCore agent process | Must remain operational to provide visibility         | Enforcement: ObRegisterCallbacks           |
| Agent binaries on disk     | Must not be replaced or deleted                       | Enforcement: FltRegisterFilter             |
| Forensic log chain         | Must be tamper-evident for incident response          | SQLite + SHA-256 hashchain                 |
| ETW telemetry session      | Must not be killed to blind the agent                 | ETW self-healing + service recovery        |

---

## 3. Adversary Profile

SentinelCore assumes an adversary who:

- Has achieved **initial code execution** on the endpoint (via phishing, exploit, or supply chain)
- Operates at **medium integrity** initially, seeking escalation to **high/system integrity**
- Uses **commodity and open-source tools** (Mimikatz, Cobalt Strike, Metasploit, custom loaders)
- May attempt **defense evasion** against EDR products
- Does **not** have kernel-level access initially (no vulnerable driver exploitation assumed)

### Out of Scope

- Bootkit/rootkit with kernel code execution (requires Secure Boot + HVCI enforcement)
- Hardware-based attacks (DMA, Evil Maid)
- Supply-chain compromise of SentinelCore itself
- Attacks from processes running as `NT AUTHORITY\SYSTEM` with kernel driver loading capability

---

## 4. Threat Catalog

### T1 — Credential Access via LSASS

| Field               | Detail                                                                                                             |
| ------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **MITRE ATT&CK**    | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) — OS Credential Dumping: LSASS Memory                  |
| **Severity**        | Critical                                                                                                           |
| **Tools Used**      | Mimikatz, procdump, comsvcs.dll MiniDump, direct `NtReadVirtualMemory`                                             |
| **Attack Sequence** | `OpenProcess(lsass.exe, PROCESS_VM_READ \| PROCESS_QUERY_INFORMATION)` → `ReadProcessMemory` / `MiniDumpWriteDump` |

**Detection Logic** (`engine/injection/handle_state.rs`):

```
1. Monitor OpenProcess calls targeting PID of lsass.exe
2. Flag when ACCESS_MASK includes PROCESS_VM_READ + PROCESS_QUERY_INFORMATION
3. Exclude known legitimate callers (WerFault.exe, csrss.exe, services.exe)
4. Correlate with subsequent memory read patterns within 10-second window
5. Confidence: HIGH if source process is unsigned or recently created
```

**False Positive Mitigation:**

- Windows Error Reporting legitimately opens lsass handles — whitelisted by image name + signature
- AV products may scan lsass memory — whitelisted by publisher certificate
- Scanner detection: processes opening >20 handles/sec to different PIDs are classified as scanners

---

### T2 — Classic Remote Thread Injection

| Field               | Detail                                                                                   |
| ------------------- | ---------------------------------------------------------------------------------------- |
| **MITRE ATT&CK**    | [T1055.003](https://attack.mitre.org/techniques/T1055/003/) — Thread Execution Hijacking |
| **Severity**        | High                                                                                     |
| **Tools Used**      | Cobalt Strike, Metasploit `migrate`, custom shellcode loaders                            |
| **Attack Sequence** | `OpenProcess` → `VirtualAllocEx(RWX)` → `WriteProcessMemory` → `CreateRemoteThread`      |

**Detection Logic** (`engine/injection/remote_thread_detector.rs`):

```
1. Track cross-process handle acquisition via ETW (Microsoft-Windows-Kernel-Process)
2. Detect VirtualAllocEx with PAGE_EXECUTE_READWRITE in foreign process
3. Detect WriteProcessMemory to the allocated region
4. Detect CreateRemoteThread with start address in the written region
5. Correlate all 4 events within a 5-second temporal window, same source PID
6. Confidence score: 0.3 (handle) + 0.3 (alloc+write) + 0.4 (thread) = 1.0
```

**Why 4-event correlation, not single-event?**

- `VirtualAllocEx` alone is used by debuggers, JIT compilers, and .NET runtime
- `CreateRemoteThread` alone is used by `kernel32!CreateProcess` internally
- Only the **complete sequence from a single source PID** constitutes injection

---

### T3 — Process Hollowing

| Field               | Detail                                                                                      |
| ------------------- | ------------------------------------------------------------------------------------------- |
| **MITRE ATT&CK**    | [T1055.012](https://attack.mitre.org/techniques/T1055/012/) — Process Hollowing             |
| **Severity**        | Critical                                                                                    |
| **Tools Used**      | Custom loaders, RunPE implementations                                                       |
| **Attack Sequence** | `CreateProcess(SUSPENDED)` → `NtUnmapViewOfSection` → `WriteProcessMemory` → `ResumeThread` |

**Detection Logic** (`engine/injection/hollowing_detector.rs`):

```
State machine with 4 stages:
  Stage 0 → Stage 1: CreateProcess with CREATE_SUSPENDED flag
  Stage 1 → Stage 2: NtUnmapViewOfSection targeting the child's base address
  Stage 2 → Stage 3: WriteProcessMemory to the child process
  Stage 3 → ALERT:   ResumeThread on the child's primary thread

Transition timeout: 10 seconds between consecutive stages
Confidence: 0.25 per stage (cumulative) → 1.0 at completion
```

**Key Indicator:** A legitimate `CreateProcess(SUSPENDED)` is common (e.g., job objects, debuggers), but `NtUnmapViewOfSection` of the child's main module is **never** performed by legitimate software. Stage 1→2 transition alone is HIGH confidence.

---

### T4 — RWX Memory Abuse

| Field              | Detail                                                                            |
| ------------------ | --------------------------------------------------------------------------------- |
| **MITRE ATT&CK**   | [T1055](https://attack.mitre.org/techniques/T1055/) — Process Injection (generic) |
| **Severity**       | Medium-High                                                                       |
| **Tools Used**     | Shellcode runners, reflective DLL loaders, Cobalt Strike Beacon                   |
| **Attack Pattern** | Allocate `PAGE_EXECUTE_READWRITE` memory in a foreign process                     |

**Detection Logic** (`engine/injection/process_memory_state.rs`):

```
1. Track all VirtualAllocEx calls with PAGE_EXECUTE_READWRITE permission
2. Maintain per-process RWX region counter (bounded HashMap, TTL 60s)
3. Alert when:
   a. RWX allocation in a FOREIGN process (cross-process) → HIGH confidence
   b. Self-RWX allocation count > 5 in 30 seconds → MEDIUM confidence
      (Exception: JIT engines like .NET CLR, V8, Java HotSpot)
4. Cross-reference with subsequent WriteProcessMemory or thread creation
```

**False Positive Mitigation:**

- .NET CLR `clrjit.dll` allocates RWX for JIT compilation — excluded by module name
- Chrome/Edge V8 engine — excluded by process image signature
- Java HotSpot — excluded by parent process and module presence

---

### T5 — APC Injection

| Field               | Detail                                                                                    |
| ------------------- | ----------------------------------------------------------------------------------------- |
| **MITRE ATT&CK**    | [T1055.004](https://attack.mitre.org/techniques/T1055/004/) — Asynchronous Procedure Call |
| **Severity**        | High                                                                                      |
| **Tools Used**      | Early Bird injection, AtomBombing (variant), custom APC payloads                          |
| **Attack Sequence** | `OpenThread` → `QueueUserAPC(target_thread, shellcode_addr)`                              |

**Detection Logic** (`engine/injection/remote_thread_detector.rs`):

```
1. Detect cross-process OpenThread with THREAD_SET_CONTEXT
2. Correlate with prior VirtualAllocEx(RWX) in the same target process
3. Detect QueueUserAPC call targeting the opened thread
4. Alert if all 3 events occur within 5-second window
5. Early Bird variant: CreateProcess(SUSPENDED) + QueueUserAPC before ResumeThread
```

---

### T6 — Handle Abuse & Privilege Escalation

| Field              | Detail                                                                          |
| ------------------ | ------------------------------------------------------------------------------- |
| **MITRE ATT&CK**   | [T1134](https://attack.mitre.org/techniques/T1134/) — Access Token Manipulation |
| **Severity**       | High                                                                            |
| **Tools Used**     | Token impersonation tools, named pipe impersonation, `DuplicateTokenEx`         |
| **Attack Pattern** | Mass-opening handles to privileged processes seeking exploitable access         |

**Detection Logic** (`engine/injection/handle_state.rs`):

```
Rolling window tracker per source PID:
  - Window size: 128 events, sliding
  - Time window: 30 seconds

Alert conditions:
  1. Single PID opens >10 handles with PROCESS_ALL_ACCESS or PROCESS_VM_WRITE
     to different target PIDs within 30 seconds → "Handle Spray" (HIGH)
  2. Single PID opens handles to >5 SYSTEM-integrity processes
     within 30 seconds → "Privilege Probing" (HIGH)
  3. DuplicateHandle from high-integrity source to low-integrity target
     with dangerous rights → "Handle Downgrade" (CRITICAL)
```

---

### T7 — Service-Based Privilege Escalation

| Field               | Detail                                                                                                         |
| ------------------- | -------------------------------------------------------------------------------------------------------------- |
| **MITRE ATT&CK**    | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) — Create or Modify System Process: Windows Service |
| **Severity**        | High                                                                                                           |
| **Tools Used**      | `sc create`, `New-Service`, direct registry manipulation                                                       |
| **Attack Sequence** | Create a new Windows service → service starts as SYSTEM → child process inherits SYSTEM token                  |

**Detection Logic** (`engine/correlation/rules.rs`):

```
Behavioral correlation rule:
  1. Detect service creation event (ETW: Microsoft-Windows-Kernel-Process)
  2. Within 30 seconds, detect child process spawn from services.exe
  3. Child process image is unsigned or from a temp directory
  4. Child process runs at HIGH or SYSTEM integrity level
  5. Alert: "Suspicious Service Escalation"
```

---

### T8 — EDR Tampering & Evasion

| Field              | Detail                                                                                                 |
| ------------------ | ------------------------------------------------------------------------------------------------------ |
| **MITRE ATT&CK**   | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) — Impair Defenses: Disable or Modify Tools |
| **Severity**       | Critical                                                                                               |
| **Attack Vectors** | `taskkill /F`, `sc stop`, ETW session termination, binary deletion, handle abuse                       |

**Multi-Layer Defense:**

| Attack                                            | Defense                                                                                                                | Layer     |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | --------- |
| `taskkill /F /IM sentinelcore.exe`                | `ObRegisterCallbacks` strips `PROCESS_TERMINATE` from all non-kernel callers                                           | Kernel    |
| `sc stop SentinelCore`                            | Service ACL removes `SERVICE_STOP` from non-admin users; service recovery restarts on failure (0s delay)               | Service   |
| `logman stop SentinelCoreETW`                     | ETW self-healing loop: `ProcessTrace` failure triggers automatic session restart                                       | User-mode |
| Delete `sentinelcore.exe`                         | `FltRegisterFilter` denies `DELETE` and `FILE_WRITE_DATA` on agent binaries                                            | Kernel    |
| Kill `sentinel_guard.exe` then `sentinelcore.exe` | Guard is a Windows service with auto-restart. Guard respawns core on exit. Mutual monitoring.                          | Service   |
| Unload `sentinel_km.sys`                          | Controlled unload requires 16-byte authorization token via IOCTL. Unauthorized unload is logged.                       | Kernel    |
| Open handle to driver device from rogue process   | `IoCreateDeviceSecure` with SDDL: only SYSTEM and Administrators. Caller PID validated against registered service PID. | Kernel    |

---

### T9 — Binary Replacement & Masquerading

| Field               | Detail                                                                                                        |
| ------------------- | ------------------------------------------------------------------------------------------------------------- |
| **MITRE ATT&CK**    | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) — Masquerading: Match Legitimate Name or Location |
| **Severity**        | Medium                                                                                                        |
| **Attack Sequence** | Rename `sentinelcore.exe`, replace with malicious binary under same name                                      |

**Detection Logic:**

```
1. MiniFilter blocks WRITE and DELETE to:
   - sentinelcore.exe
   - sentinel_km.sys
   - sentinel_config.yaml
   (Except from the protected process itself)

2. On startup, sentinelcore.exe computes SHA-256 of its own binary
   and stores the hash in memory (engine/integrity.rs)

3. Periodic integrity check (every 60s): re-hash binary on disk,
   compare with stored hash. Mismatch → CRITICAL alert

4. Any modification attempt logged to tamper-evident hashchain
   (storage/hashchain.rs — SHA-256 chained records in SQLite)
```

---

## 5. Attack Chain Analysis

### Scenario: Cobalt Strike Post-Exploitation

```
┌─────────────────────────────────────────────────────────────────────┐
│ PHASE 1: Initial Access (out of scope — assumed compromised)       │
│   Attacker has beacon running as user "john" (medium integrity)    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│ PHASE 2: Credential Access                                         │
│   beacon.exe → OpenProcess(lsass.exe, PROCESS_VM_READ)             │
│   ┌─────────────────────────────────────────────────────────┐      │
│   │ ★ DETECTED by T1: LSASS handle monitor                 │      │
│   │   Source PID matches no whitelist → ALERT (HIGH)        │      │
│   └─────────────────────────────────────────────────────────┘      │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│ PHASE 3: Lateral Movement via Injection                            │
│   beacon.exe → OpenProcess(explorer.exe)                           │
│   beacon.exe → VirtualAllocEx(explorer.exe, RWX)                   │
│   beacon.exe → WriteProcessMemory(explorer.exe, shellcode)         │
│   beacon.exe → CreateRemoteThread(explorer.exe, shellcode_addr)    │
│   ┌─────────────────────────────────────────────────────────┐      │
│   │ ★ DETECTED by T2: Remote Thread Injection               │      │
│   │   4/4 stages matched within 5s window → ALERT (CRITICAL)│      │
│   └─────────────────────────────────────────────────────────┘      │
│   ┌─────────────────────────────────────────────────────────┐      │
│   │ ★ DETECTED by T4: RWX allocation in foreign process     │      │
│   │   Cross-process RWX → correlated with T2 → ALERT (HIGH) │      │
│   └─────────────────────────────────────────────────────────┘      │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│ PHASE 4: Defense Evasion                                           │
│   Attacker attempts: taskkill /F /IM sentinelcore.exe              │
│   ┌─────────────────────────────────────────────────────────┐      │
│   │ ★ BLOCKED by T8: ObCallback strips PROCESS_TERMINATE    │      │
│   │   Kernel telemetry pushed → Ring Buffer → User-mode log  │      │
│   └─────────────────────────────────────────────────────────┘      │
│   Attacker attempts: del sentinelcore.exe                          │
│   ┌─────────────────────────────────────────────────────────┐      │
│   │ ★ BLOCKED by T9: MiniFilter denies DELETE on binary      │      │
│   │   STATUS_ACCESS_DENIED returned to attacker process      │      │
│   └─────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. Detection Coverage Matrix

| MITRE Tactic         | Technique ID | Technique Name          | Detection         | Confidence | Engine Module                         |
| -------------------- | ------------ | ----------------------- | ----------------- | ---------- | ------------------------------------- |
| Credential Access    | T1003.001    | LSASS Memory Dump       | ✅ Detect         | HIGH       | `injection/handle_state.rs`           |
| Execution            | T1055.003    | Remote Thread Injection | ✅ Detect         | CRITICAL   | `injection/remote_thread_detector.rs` |
| Execution            | T1055.012    | Process Hollowing       | ✅ Detect         | CRITICAL   | `injection/hollowing_detector.rs`     |
| Execution            | T1055        | RWX Abuse               | ✅ Detect         | HIGH       | `injection/process_memory_state.rs`   |
| Execution            | T1055.004    | APC Injection           | ✅ Detect         | HIGH       | `injection/remote_thread_detector.rs` |
| Privilege Escalation | T1134        | Handle Abuse            | ✅ Detect         | HIGH       | `injection/handle_state.rs`           |
| Privilege Escalation | T1543.003    | Service Escalation      | ✅ Detect         | MEDIUM     | `correlation/rules.rs`                |
| Defense Evasion      | T1562.001    | EDR Tampering           | ✅ Block + Detect | CRITICAL   | `sentinel_km.sys`                     |
| Defense Evasion      | T1036.005    | Binary Replace          | ✅ Block + Detect | HIGH       | `minifilter.c` + `integrity.rs`       |

### Not Covered (Out of Scope v1.0)

| Technique ID | Technique Name                  | Reason                                                                  |
| ------------ | ------------------------------- | ----------------------------------------------------------------------- |
| T1014        | Rootkit                         | Requires Secure Boot + HVCI; kernel-level attacker assumed out of scope |
| T1027        | Obfuscated Files                | Requires static analysis / sandbox; not real-time ETW detectable        |
| T1071        | Application Layer Protocol (C2) | Requires network DPI; SentinelCore is endpoint-focused                  |
| T1190        | Exploit Public-Facing App       | Initial access prevention is not SentinelCore's role                    |

---

## 7. Assumptions & Limitations

### Assumptions

1. **Windows Secure Boot is enabled** — prevents unsigned bootloaders from pre-empting the kernel
2. **Driver signing enforcement is active** — only signed drivers can load (SentinelCore requires EV + WHQL for production)
3. **Attacker does not have kernel code execution** — if they can load a vulnerable driver (BYOVD), they can bypass ObCallbacks
4. **ETW providers are functional** — if Windows ETW subsystem is fundamentally compromised (e.g., `EtwEventWrite` patched in ntdll), telemetry is lost

### Known Limitations

1. **User-mode ntdll unhooking** — If attacker maps a fresh copy of ntdll to bypass ETW user-mode hooks, SentinelCore still detects via kernel ETW providers which cannot be unhooked from user-mode
2. **Direct syscalls** — Attackers using direct syscalls (`Nt*` stubs) bypass ntdll instrumentation. SentinelCore relies on kernel-mode ETW providers to mitigate this
3. **Time-of-check/time-of-use** — Between detection and response, the attack may partially succeed. SentinelCore prioritizes forensic completeness over real-time blocking in user-mode
4. **Single-endpoint scope** — Cross-endpoint correlation (e.g., lateral movement detection across machines) requires a SIEM or cloud analytics layer consuming SentinelCore telemetry
