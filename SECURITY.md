# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: |

## Reporting a Vulnerability

SentinelCore is a defensive security research tool. We take security seriously.

**If you discover a vulnerability in this project, please do NOT open a public GitHub issue.**

Instead, report it privately:

1. **Email:** open a private security advisory on the GitHub repository
2. **Response time:** We aim to acknowledge all reports within 48 hours
3. **Disclosure:** We follow responsible disclosure — we will credit reporters in the patch notes

## Scope

The following are **in scope** for security reports:

- Memory safety issues in the kernel driver (`driver/`)
- Privilege escalation via the IOCTL communication channel
- Bypass of the shutdown authorization token mechanism
- Integrity failures in the audit hash chain (`agent/src/audit/`)
- Sensitive data exposure in log output

## Out of Scope

- Issues requiring physical machine access
- Theoretical attacks with no practical exploit path
- Bugs in third-party dependencies (report upstream)

## Legal Notice

> This project is a **defensive security research tool** designed exclusively for
> authorized testing and educational environments. Unauthorized use against
> systems you do not own or have explicit permission to test is prohibited and
> may be illegal under applicable law. The authors assume no liability for misuse.
