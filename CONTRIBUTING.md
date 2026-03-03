# Contributing to SentinelCore

Thank you for your interest in contributing to SentinelCore.

## Before You Contribute

Please read the [SECURITY.md](./SECURITY.md) file. This project touches kernel-level
code. Incorrect changes can cause system instability or BSODs.

## How to Contribute

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/your-feature-name`
3. **Make your changes** following the code style below
4. **Run checks**: `cargo fmt && cargo clippy && cargo check`
5. **Open a Pull Request** with a clear description of the change

## Code Style

- Rust: Follow `rustfmt` defaults (`cargo fmt`)
- C (kernel driver): Follow WDK coding conventions
- No `TODO fix later` comments in submitted code
- All `unsafe` blocks must have a safety comment explaining why it is safe

## What We Accept

- Bug fixes with a clear reproduction case
- Performance improvements with benchmarks
- Documentation improvements
- New telemetry event types following existing patterns

## What We Don't Accept

- Offensive capabilities (exploit payloads, shellcode, etc.)
- Changes that disable or weaken the integrity verification system
- Hardcoded credentials or endpoint URLs

## Testing

Before submitting, ensure:

```bash
cd agent && cargo check && cargo test
cd ../watchdog && cargo check
```

All tests must pass with 0 errors and 0 warnings.
