<p align="center">
  <h1 align="center">🛡️ SentinelCore</h1>
  <p align="center">
    <strong>Enterprise Endpoint Detection & Response Agent for Windows</strong>
  </p>
  <p align="center">
    Kernel-hardened · Behavioral correlation · Tamper-evident forensics
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" alt="Rust">
    <img src="https://img.shields.io/badge/kernel-C%2FWDK-blue?style=flat-square" alt="C/WDK">
    <img src="https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D6?style=flat-square" alt="Windows">
    <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
    <img src="https://img.shields.io/badge/security-SECURITY.md-orange?style=flat-square" alt="Security Policy">
    <img src="https://img.shields.io/badge/build-passing-brightgreen?style=flat-square" alt="Build">
  </p>
</p>

---

## Overview

SentinelCore is a production-grade EDR agent that detects post-exploitation activity on Windows endpoints using real-time ETW telemetry, multi-stage behavioral correlation, and kernel-level self-protection. It is designed to identify credential theft, process injection, handle abuse, and privilege escalation — the techniques used by advanced adversaries after initial compromise.

**This is not a signature scanner.** SentinelCore correlates sequences of events across temporal windows to detect attack chains with high confidence and low false-positive rates.

> [!WARNING]
> **Defensive Research Tool Only.**
> SentinelCore is designed exclusively for **authorized testing environments** and security research.
> It is not intended for use against systems you do not own or have explicit written permission to test.
> See [SECURITY.md](./SECURITY.md) for the responsible disclosure policy.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    KERNEL MODE                              │
│  sentinel_km.sys                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ ObCallbacks   │  │ MiniFilter   │  │ Ring Buffer      │  │
│  │ Handle Strip  │  │ File Protect │  │ (Telemetry Out)  │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         └─────────────────┴───────────────────┘             │
│                           │ IOCTL                           │
├───────────────────────────┼─────────────────────────────────┤
│                    USER MODE                                │
│  sentinelcore.exe (Rust)                                    │
│  ┌────────┐ ┌──────────┐ ┌────────────┐ ┌──────────────┐   │
│  │ ETW    │→│ Pipeline │→│ Detection  │→│ Forensic     │   │
│  │ Sensor │ │ Workers  │ │ Engine     │ │ Storage      │   │
│  └────────┘ └──────────┘ └────────────┘ └──────────────┘   │
│  ┌────────┐ ┌──────────┐ ┌────────────┐                    │
│  │ Health │ │ Cloud    │ │ Kernel     │                    │
│  │ Monitor│ │ Uploader │ │ Comms      │                    │
│  └────────┘ └──────────┘ └────────────┘                    │
├─────────────────────────────────────────────────────────────┤
│  sentinel_guard.exe (Watchdog Service)                      │
└─────────────────────────────────────────────────────────────┘
```

> Full architecture diagram with data flow: [ARCHITECTURE.md](ARCHITECTURE.md)

---

## Features

### Detection Engine

| Capability              | Technique                                            | MITRE ATT&CK |
| ----------------------- | ---------------------------------------------------- | ------------ |
| LSASS Credential Dump   | Handle monitor + memory read correlation             | T1003.001    |
| Remote Thread Injection | 4-event sequence matching within 5s window           | T1055.003    |
| Process Hollowing       | 4-stage state machine with confidence scoring        | T1055.012    |
| RWX Memory Abuse        | Cross-process allocation tracking with JIT exclusion | T1055        |
| APC Injection           | Thread context + allocation correlation              | T1055.004    |
| Handle Spray / Abuse    | Rolling window anomaly detection (128 events)        | T1134        |
| Service Escalation      | Behavioral rule: service create → SYSTEM child       | T1543.003    |

### Kernel Protection

| Capability             | Mechanism                                                             |
| ---------------------- | --------------------------------------------------------------------- |
| Anti-Kill              | `ObRegisterCallbacks` strips `PROCESS_TERMINATE` from foreign callers |
| File Tamper Protection | `FltRegisterFilter` denies writes to agent binaries                   |
| Secure IOCTL Surface   | `IoCreateDeviceSecure` + SDDL ACL (SYSTEM + Admins only)              |
| Caller Validation      | First IOCTL caller locks as authorized service PID                    |
| Controlled Unload      | 16-byte token required; unauthorized unload logged                    |
| Telemetry Export       | Non-paged spinlock ring buffer (4096 events, FIFO eviction)           |

### Forensic Storage

| Capability             | Implementation                                      |
| ---------------------- | --------------------------------------------------- |
| Append-Only Event Log  | SQLite WAL mode, dedicated writer thread            |
| Tamper-Evident Chain   | SHA-256 hashchain — every record chains to previous |
| Non-Blocking Ingestion | Bounded channel decouples pipeline from disk I/O    |
| Crash-Safe             | WAL mode + `PRAGMA synchronous=NORMAL`              |

### Cloud Telemetry

| Capability      | Implementation                                   |
| --------------- | ------------------------------------------------ |
| Device Identity | Ed25519 keypair, DPAPI-protected private key     |
| Enrollment      | mTLS with challenge-response attestation         |
| Upload          | Compressed (flate2) batches with backpressure    |
| Offline Mode    | Spool to disk, upload when connectivity restores |

### Resilience

| Capability       | Implementation                                        |
| ---------------- | ----------------------------------------------------- |
| Process Watchdog | `sentinel_guard.exe` respawns core on crash (<1s)     |
| Service Recovery | Windows SCM: restart on failure (0s delay)            |
| ETW Self-Healing | Auto-restart ETW session on `ProcessTrace` failure    |
| Binary Integrity | SHA-256 self-check on startup + periodic verification |

---

## Project Structure

```
SentinelCore/
├── docs/                           # Engineering Documentation
│   ├── architecture.md             #   System diagrams & module inventory
│   ├── threat_model.md             #   MITRE ATT&CK threat catalog
│   ├── kernel_stability_design.md  #   IRQL discipline & safety proofs
│   └── test_strategy.md            #   Validation methodology
│
├── agent/                          # User-mode detection agent (Rust)
│   ├── src/
│   │   ├── sensor/                 #   ETW multi-provider listener
│   │   ├── pipeline/               #   EventBus, worker pool, backpressure
│   │   ├── engine/                 #   Signature, context, correlation
│   │   │   ├── correlation/        #     Temporal behavioral engine
│   │   │   └── injection/          #     Injection & handle abuse detection
│   │   ├── storage/                #   SQLite forensic store + hashchain
│   │   ├── health/                 #   Atomic metrics, heartbeat, exporter
│   │   └── cloud/                  #   Identity, enrollment, uploader, IOCTL client
│   ├── rules/                      #   YAML detection signatures
│   └── Cargo.toml
│
├── sentinel_guard/                 # Watchdog process (Rust)
│   └── src/main.rs
│
└── driver/                         # Kernel driver (C/WDK)
    ├── globals.h                   #   State, pool tags, IOCTL codes, SAL
    ├── driver.c                    #   DriverEntry / DriverUnload
    ├── handle_protect.c            #   ObRegisterCallbacks (process protection)
    ├── minifilter.c                #   FltRegisterFilter (file protection)
    ├── comms.c                     #   Secure device + IOCTL dispatch
    ├── ringbuffer.c                #   Non-paged telemetry ring buffer
    └── sentinel_km.inf             #   Driver installation manifest
```

---

## Building

### Prerequisites

| Component                | Version               | Purpose                     |
| ------------------------ | --------------------- | --------------------------- |
| Rust                     | stable (2021 edition) | User-mode agent             |
| Visual Studio            | 2022+                 | Kernel driver compilation   |
| Windows Driver Kit (WDK) | 10.0.22621+           | Kernel headers, libs, tools |
| Windows 10/11 SDK        | 10.0.22621+           | User-mode Windows API       |

### User-Mode Agent

```powershell
cd agent
cargo build --release
```

### Kernel Driver

1. Open `driver/` as a WDM Driver project in Visual Studio
2. Add all `.c` and `.h` files to the project
3. Add `FltMgr.lib` to Linker → Additional Dependencies
4. Build → Release → x64
5. Output: `sentinel_km.sys` + `sentinel_km.inf` + `sentinel_km.cat`

### Installation

```powershell
# Enable test signing (development only)
bcdedit /set testsigning on
# Reboot

# Install driver
pnputil /add-driver sentinel_km.inf /install

# Start driver
sc start sentinel_km

# Run agent
.\target\release\core.exe
```

> ⚠️ **Production deployment requires an EV code signing certificate and WHQL attestation signing.**

---

## Documentation

| Document                                                   | Description                                                                                             |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| [Architecture](docs/architecture.md)                       | System diagrams, data flow, module inventory, technology justification                                  |
| [Threat Model](docs/threat_model.md)                       | 9 threat scenarios with MITRE ATT&CK mappings, detection logic, attack chains, coverage matrix          |
| [Kernel Stability Design](docs/kernel_stability_design.md) | IRQL discipline, lock ordering proof, deadlock avoidance, performance budgets, verification methodology |
| [Test Strategy](docs/test_strategy.md)                     | Unit validation, kernel stability testing, telemetry integrity, performance considerations              |

---

## Design Principles

| Principle                         | Implementation                                                                                                  |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Kernel minimalism**             | ~800 LOC of C. No detection logic. No complex data structures. Auditable in one sitting.                        |
| **Detection in memory-safe code** | All correlation, pattern matching, and alerting in Rust. Zero buffer overflows possible.                        |
| **No hooks, no patches**          | Only official Microsoft APIs: `ObRegisterCallbacks`, `FltRegisterFilter`, ETW. PatchGuard-safe.                 |
| **Soft deny over hard block**     | Strip access rights instead of returning `STATUS_ACCESS_DENIED`. System continues to function.                  |
| **Behavioral correlation**        | Multi-event temporal windows, not single-event heuristics. High confidence, low false positives.                |
| **Forensic completeness**         | Every event persisted to tamper-evident hashchain. Even if attacker succeeds, the trail is preserved.           |
| **Fail-safe degradation**         | Agent crash → watchdog restart (<1s). ETW kill → self-healing. Disk full → detection continues without logging. |

---

## Security Model

```
Threats we detect:          Threats we defend against:      Out of scope:
├─ Credential dumping       ├─ Process termination          ├─ Bootkits/rootkits
├─ Process injection        ├─ Binary tampering             ├─ Hardware attacks
├─ Process hollowing        ├─ Service disruption           ├─ Supply chain
├─ Handle abuse             ├─ ETW session killing          ├─ Initial access
├─ Privilege escalation     ├─ Driver unload                │  prevention
└─ APC injection            └─ IOCTL abuse                  └─ Network DPI
```

---

## Tech Stack

| Layer                  | Technology        | Rationale                                                                    |
| ---------------------- | ----------------- | ---------------------------------------------------------------------------- |
| User-mode core         | **Rust**          | Memory safety, zero-cost abstractions, `crossbeam` channels, `windows` crate |
| Kernel driver          | **C (WDK)**       | WDK requirement. Minimal surface. SAL-annotated.                             |
| Telemetry source       | **ETW**           | Official kernel telemetry. Stable API. No hooking.                           |
| Forensic storage       | **SQLite (WAL)**  | Crash-safe. 100K+ inserts/sec. Single-file database.                         |
| Cryptographic identity | **Ed25519**       | Fast signing. Small keys. Deterministic.                                     |
| Rule format            | **YAML**          | Human-readable. Hot-reloadable via `arc-swap`.                               |
| Compression            | **flate2 (zlib)** | Fast compression for cloud upload batches.                                   |

---

## License

Proprietary. All rights reserved.

---

<p align="center">
  <sub>Built with Rust 🦀 and WDK 🪟 — Enterprise-grade endpoint security.</sub>
</p>
