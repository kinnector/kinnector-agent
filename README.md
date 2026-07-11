# Kinnector Agent

Kinnector Agent is the host-level security daemon written in Rust. It functions as the central decision engine, receiving raw telemetry from `kinnector-core`, evaluating behavioral heuristics, and executing local containment actions (such as process suspension, SIGKILL termination, or network blocking).

---

## Why this exists

Operating system telemetry engines capture massive volumes of raw events but do not maintain process state context or evaluate policies. 

Kinnector Agent solves this by running as a user-space daemon that tracks active process trees in memory, matches event sequences against security rules, and performs low-latency containment before malicious operations complete.

---

## Architecture and Mental Model

```
                  ┌──────────────────────────┐
                  │      kinnector-core      │ (Low-level Telemetry Engine)
                  └─────────────┬────────────┘
                                │
                    Raw Binary Telemetry IPC
                    (/var/run/kinnector/telemetry.sock)
                                │
                                ▼
                  ┌──────────────────────────┐
                  │     kinnector-agent      │ ──[Hot-reloads /etc/kinnector/rules.db]
                  │    (Rust EDR Daemon)     │
                  └─────┬──────────────┬─────┘
                        │              │
      JSON Lines Alerts Log            │ CLI IPC / JSON-RPC
      (/var/log/kinnector/alerts.log)  │ (/var/run/kinnector/control.sock)
                        │              │
                        ▼              ▼
               ┌────────────────┐  ┌──────────────┐
               │ Svelte Desktop │  │antitheft-cli │
               └────────────────┘  └──────────────┘
```

The agent maintains an in-memory state engine tracking running processes. It maps incoming events from `kinnector-core` to the active process tree to detect behaviors such as rapid credential reading, persistence modifications, package manager supply chain exploits, or socket duplication (reverse shells).

---

## Inter-Process Communication (IPC)

The daemon coordinates three primary communication channels:

### 1. Telemetry Socket
* **Socket Path**: `/var/run/kinnector/telemetry.sock` (restricted to `0o600` owned by root).
* **Protocol**: Receives packed C-struct payloads (`TelemetryEventRaw`, 1566 bytes frame size).
* **Authentication**: Enforces length-prefixed token validation on connection.

### 2. Control Socket
* **Socket Path**: `/var/run/kinnector/control.sock` (restricted to `0o600`).
* **Protocol**: Exposes JSON-RPC endpoints for `antitheft-cli` and `antitheft`.
* **Request Schema (`CliRequest`)**:
  ```json
  { "type": "Status" }
  { "type": "ReloadRules" }
  { "type": "ReleaseContainment", "payload": 1234 }
  { "type": "ListProcesses" }
  { "type": "ListRules" }
  { "type": "TrustOnce", "payload": 1234 }
  ```
* **Response Schema (`CliResponse`)**:
  ```json
  { "status": "Success", "payload": { ... } }
  { "status": "Error", "payload": "Description of the error" }
  ```

### 3. Structured Alerts Log
* **Log Path**: `/var/log/kinnector/alerts.log`
* **Format**: Newline-delimited JSON (JSON Lines). Each entry specifies the threat event and containment resolution:
  ```json
  {
    "ts": "2026-07-08T20:52:00Z",
    "severity": "CRITICAL",
    "category": "credential_access",
    "rule_path": "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "process": {
      "pid": 10452,
      "ppid": 9941,
      "exe": "/usr/bin/python3",
      "cmdline": "python3 setup.py install"
    },
    "action": "TERMINATED",
    "message": "Package install process attempted to read sensitive credentials"
  }
  ```

---

## Operating System Compatibility

Kinnector Agent is optimized for modern Linux environments. It leverages kernel-level containment when supported, falling back to user-space hooks when necessary.

### 1. BPF LSM Mode (Recommended)
Provides kernel-level enforcement via Linux Security Modules:
* Ubuntu 22.04 LTS & 24.04 LTS (Kernels 5.15 / 6.8)
* Debian 12 (Kernel 6.1)
* Fedora 39+ (Kernel 6.5+)
* RHEL / Rocky Linux 9.x (Kernel 5.14)
* Arch Linux (Kernel 6.x)

### 2. User-Mode Fallback Mode
Monitors events via user-space hooks when BPF LSM is unavailable:
* Ubuntu 18.04 LTS & 20.04 LTS
* Debian 10 & 11
* RHEL / Rocky Linux 8.x

---

## Build and Execution

### Prerequisites
* Stable Rust toolchain (Rust 1.75+)

### Compiling
Build the release daemon binary:

```bash
cargo build --release
```

### Running Locally
Run the agent (requires root privileges to create socket files and execute containment actions):

```bash
sudo ./target/release/kinnect-agent
```