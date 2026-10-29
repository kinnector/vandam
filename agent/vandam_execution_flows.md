# vandam Process Execution & Heuristic Pipeline Guide

This guide details how **Vandam** manages process execution restrictions, detects shell/PTY spawns, identifies reverse shells, and processes events depending on whether they originate from a **Monitored Server Context** or an **Install Context**.

---

## 🛡️ 1. Process Execution Restriction Profiles (Modes)

Vandam implements five distinct process-level restriction profiles configured either dynamically via auto-discovery (e.g., database discovery) or declaratively (via `/etc/vandam/conf.d/*.json`).

| Profile Flags | Profile Name | Target / Trigger | Enforced Action on Exec (`ProcessCreate`) |
| :--- | :--- | :--- | :--- |
| `PROFILE_ZERO_EXECUTION`<br>`(0x10000000)` | **Zero Execution Mode** (Strict No-Exec) | Databases (unless degraded by complexity), container services with `zero-execution`, or manually configured processes. | **SIGKILL** child process (if it is a spawned utility/shell) or **BLOCK** execution in-kernel via eBPF if it is a main server process itself (preventing production outages).<br>Raises: `Threat.Server.ZeroExecutionViolation` |
| `PROFILE_RESTRICTED_EXEC`<br>`(0x20000000)` | **Restricted Execution Mode** | Mail servers, manual configurations, or whenever the allowlist is seeded from git. | **SIGKILL** child process (or **BLOCK** in-kernel if it is a main server process) if `child_exe` is not a system path (e.g. `/bin/`, `/usr/bin/`) **AND** is not registered in the global inode allowlist.<br>Raises: `Threat.Server.ExploitInjection` |
| `PROFILE_PATH_CONSTRAINED`<br>`(0x08000000)` | **Path Constrained Mode** | Configured processes. | Restricts operations of the process to registered data directories or web root paths. |
| `PROFILE_ZERO_NETWORK`<br>`(0x80000000)` | **Zero Network Mode** | Configured container/DB processes. | Restricts network outbound operations at the kernel BPF layer (excluding replica/sentinel IP allowlists). |
| *None (Default / Audit)* | **No Restriction Mode** | Processes without specific profiles. | Permissive execution. If learning mode is enabled, dynamically seeds allowlist entries instead of blocking. |

---

## 🔄 2. Process Context Classification & Inheritance

When an eBPF/telemetry event occurs, Vandam classifies the process context and propagates it down the process tree:

```mermaid
graph TD
    A[Telemetry Event: ProcessCreate] --> B{Parent tracked in process_map?}
    B -- Yes --> C[Inherit Parent Context:<br>is_listening_server, is_install_context,<br>install_root_pid, depth = parent.depth + 1]
    B -- No --> D[Resolve Parent via /proc/ppid/exe]
    D --> E{Is parent web or listening?}
    E -- Yes --> F[Set is_parent_web = true]
    E -- No --> G[Set is_parent_web = false]
    C --> H[Determine Child Flags]
    F --> H
    G --> H
    H --> I{Is child exe an installer binary?<br>(npm, pip, composer, etc.)}
    I -- Yes --> J[Set is_child_install = true<br>final_install_root = child_pid]
    I -- No --> K[Set is_child_install = false<br>final_install_root = parent.install_root]
    J --> L[Insert into process_map: ProcessNode]
    K --> L
    L --> M[Proceed to Heuristics Pipeline]
```

*   **Context Propagation:** A child process strictly inherits its parent's flags (e.g., `is_listening_server`, `is_install_context`, and extra allowlisted paths). This prevents child processes from evading checks or expanding directory access privileges by spawning subshells.

---

## 📊 3. Context Heuristics Pipeline

Depending on the context, Vandam executes tailored security heuristics.

```mermaid
graph TD
    Start[Process Telemetry Received] --> Context{Context Type?}
    
    %% Install Context Branch
    Context -- Install Context --> InsExec{Event Type?}
    InsExec -- ProcessCreate --> InsDepth{Subprocess Depth >= 2?}
    InsDepth -- Yes --> InsWarn[Audit Warning: Threat.Server.BinaryOrSourcePoisoned]
    InsDepth -- No --> InsAllow[Allow spawn]
    
    InsExec -- Dup2 --> InsRS{socket dup'd to stdin/out/err?}
    InsRS -- Yes --> InsRSKill[SIGKILL: Vulnerability.SupplyChain.ReverseShell]
    
    InsExec -- FileOpen/Create/Write --> InsPTY{Is PTY Creation?<br>(/dev/ptmx, etc.)}
    InsPTY -- Yes --> InsPTYKill[SIGKILL: Vulnerability.SupplyChain.PtyReverseShell]
    InsPTY -- No --> InsSock{Docker / Containerd Socket?}
    InsSock -- Yes --> InsSockKill[SIGKILL: Vulnerability.SupplyChain.DockerSocketAccess]
    InsSock -- No --> InsEnv{Is pre-existing .env file read?}
    InsEnv -- Yes --> InsEnvWarn[Warning: Warning.SupplyChain.CredentialExfiltrationAttempt]
    InsEnv -- No --> InsFFI{Is FFI/ctypes library read?}
    InsFFI -- Yes --> InsFFIWarn[Warning: Warning.SupplyChain.FFICapabilityLoaded]
    InsFFI -- No --> InsPersist{Is persistence path written?<br>(cron, systemd, profile)}
    InsPersist -- Yes --> InsPersistKill[SIGKILL: Vulnerability.SupplyChain.PersistenceAttempt]
    InsPersist -- No --> InsNormal[Allow File Action]
    
    InsExec -- NetworkConnect --> InsNetDepth{Subprocess Depth >= 2?}
    InsNetDepth -- Yes --> InsNetWarn[Audit Warning: Threat.Server.BinaryOrSourcePoisoned outbound connect]
    
    %% Monitored Server Context Branch
    Context -- Monitored Server Context --> WebExec{Event Type?}
    
    WebExec -- ProcessCreate --> WebGit{Is child exe 'git'?}
    WebGit -- Yes --> WebGitAudit[Audit: Telemetry.Audit.GitExecution]
    WebGit -- No --> WebStorage{Spawned from Storage or /tmp?}
    WebStorage -- Yes --> WebStorKill[SIGKILL child: Threat.Upload.ExecutionFromStorageDir]
    WebStorage -- No --> WebShell{Is shell interpreter?<br>(sh, bash, zsh)}
    WebShell -- Yes --> WebShellKill[SIGKILL child: Threat.Server.ShellSpawnAttempt]
    WebShell -- No --> WebZero{Is Zero/Restricted Exec active?}
    WebZero -- Yes --> WebZeroCheck{Violates policy?}
    WebZeroCheck -- Yes --> WebZeroKill[BLOCK / SIGKILL child: ZeroExecutionViolation / ExploitInjection]
    WebZeroCheck -- No --> WebAllow
    WebZero -- No --> WebAllow
    
    WebExec -- Dup2 --> WebRS{socket dup'd to stdin/out/err?}
    WebRS -- Yes --> WebRSKill[BLOCK / SIGKILL child: Threat.Server.ReverseShell]
    
    WebExec -- FileOpen/Read --> WebRO{Read unregistered file?}
    WebRO -- Yes --> WebQuarRO[Quarantine file + Alert: Threat.Server.UnregisteredFileRead]
    
    WebExec -- FileCreate/Write --> WebSO{Write Shared Library (.so)?}
    WebSO -- Yes --> WebSOKill[Quarantine .so + Alert: Threat.Server.SOInjectionBlocked]
    WebSO -- No --> WebWR{Write unregistered file?}
    WebWR -- Yes --> WebQuarWR[Quarantine file + Alert: Threat.Server.UnregisteredFileWrite]
    
    WebExec -- MemoryMap/Protect --> WebMem{Map/Protect PROT_EXEC on anonymous page?}
    WebMem -- Yes --> WebMemDepth{Subprocess Depth > 0?}
    WebMemDepth -- Yes --> WebMemKill[BLOCK: Threat.Server.MemoryShellcode]
    WebMemDepth -- No --> WebMemJit{Is JIT runtime or CAP_SYS_PTRACE?}
    WebMemJit -- No --> WebMemKill
    WebMemJit -- Yes --> WebMemWarn[Emit alert only]
    
    WebExec -- PtraceAttach --> WebPt[Process attaches debugger]
    WebPt --> WebPtKill[BLOCK: Threat.Server.DebuggerAttach]
    
    WebExec -- FileDelete --> WebDel{Deletes system logs/bins?}
    WebDel -- Yes --> WebDelKill[BLOCK: Threat.Server.CriticalFileDeleted]
    
    WebExec -- IPCAccess --> WebIPC{Attaches segment owned by root?}
    WebIPC -- Yes --> WebIPCKill[BLOCK: Threat.Server.IPCSecurityViolation]
    
    WebExec -- PrivilegeChange --> WebPriv{Escalating non-root to root?}
    WebPriv -- Yes --> WebPrivKill[BLOCK: Threat.Server.PrivilegeEscalation]
```

---

## 🔍 4. Handling Core Threats (PTYs, Shells, Reverse Shells)

### 🐚 Shells & Exec Spawns
Vandam restricts child process spawning from web/monitored parents strictly:
*   **Shell Interpreters:** Executing bash, sh, dash, zsh, etc. is blocked (`Threat.Server.ShellSpawnAttempt`).
*   **Storage Execution:** Spawning any binary located in upload, session, temp directories, or `/tmp/`, `/var/tmp/`, `/dev/shm/` is blocked (`Threat.Upload.ExecutionFromStorageDir`).
*   **Selective Containment:** Spawned child utility/shell processes are terminated immediately with `SIGKILL`. Main web servers or database processes are **never** SIGKILLed; their execution is blocked in-kernel by eBPF returning `-EACCES`, keeping the production service alive.
*   **Git Execution & Write Auditing:**
    *   *Git Execution:* Executions of the `git` binary by monitored processes are audited via `Telemetry.Audit.GitExecution`. They are allowed to proceed without blocking (zero operational friction).
    *   *Git Writes:* Writing git commands (`commit`, `add`, etc.) trigger `Telemetry.Audit.GitWriteOperation` if executed outside of `god_mode`/`local_ssh`.
    *   *Git Configuration Tampering:* Attempts by unauthorized processes to write to `/.git/config` or `/.git/hooks/` trigger `Telemetry.Audit.GitTamperingAttempt` alerts but are allowed to execute.

### 🔌 Reverse Shells
Reverse shells are identified when a socket descriptor is mapped onto stdin, stdout, or stderr via the `dup2` system call.
*   **Signature:** `EventType::Dup2` where `old_fd_type == 2` (network socket) and `new_fd == 0 \| 1 \| 2`.
*   **Mitigation:** SIGKILL the process tree immediately (or block the action in-kernel if the target is a web server or database process).
    *   *Web/Monitored Server Context:* Emits `Threat.Server.ReverseShell`.
    *   *Install Context:* Emits `Vulnerability.SupplyChain.ReverseShell`.

### 🖥️ Pseudo-Terminal (PTY) Spawns
PTY creations are detected by checking file open descriptors.
*   **Signature:** `EventType::FileOpen` where the target file is `/dev/ptmx`, `/dev/pts/ptmx`, or starts with `/dev/pts/`.
*   **Mitigation:**
    *   *Install Context:* Terminated with `SIGKILL` immediately. (Raises: `Vulnerability.SupplyChain.PtyReverseShell`).
    *   *Monitored Context:* Allowed implicitly as part of monitored admin terminal sessions (tracked under SSH logs/TTY logging).
    *   *Other Unmonitored Context:* Dispatches a immediate HIGH severity alert (`Telemetry.Anomaly.PTYCreated`) to the fleet console for security audit, but does not block.

### ⏰ Cron-Scheduled Path Protection
Vandam implements proactive protection against scheduled script hijack attempts:
*   **Mechanism:** Vandam scans system crontabs (`/etc/crontab`, `/etc/cron.d/*`), user crontabs (`/var/spool/cron/*`), and standard script directories (`/etc/cron.daily/`, etc.) on startup to resolve all files and executables scheduled by cron. Additionally, any write, create, rename, or delete event targeting a crontab file triggers an automatic dynamic refresh of the registry in real-time, allowing dynamic updates (like removing or adding rules in god mode) to take effect instantly.
*   **Mitigation:** Any write, create, or rename operation targeting these files is blocked. If the caller is a spawned child process (and not a main web server or database), it is terminated with `SIGKILL`.
    *   *Install Context:* Emits `Vulnerability.SupplyChain.CronHijackAttempt`.
    *   *Monitored Server Context:* Emits `Threat.Server.CronHijackAttempt`.
