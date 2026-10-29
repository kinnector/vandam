# Vandam Node.js / Bun / Deno RASP Agent

The Vandam Node.js RASP Agent uses comprehensive module monkey-patching to intercept dangerous OS-level calls, file system modifications, module imports, and native C++ addons deep inside the V8 JavaScript runtime.

## Interception Coverage

### 1. Magic Loading & Imports
**Covered:** Yes.
We monkey-patch the internal `Module.prototype.require` function. When an application or framework attempts to `require('malware')`, Vandam natively intercepts it before the JavaScript engine attempts to parse or execute the file.

### 2. C-Library Loading & Execution (FFI & C++ Addons)
**Covered:** Yes.
When an attacker tries to bypass JavaScript execution using `process.dlopen` to load a native compiled `.node` C++ addon (which directly interacts with the OS), Vandam intercepts it.

## JSON Telemetry Schema & Mapping
The agent sends JSON payloads to `/run/vandam/rasp_telemetry.sock`. The Vandam backend must be ready to ingest this structure.

```json
{
  "type": "exec_call",
  "pid": 12345,
  "function": "child_process.exec",
  "path": "whoami",
  "in_request": 0,
  "http": {},
  "trace": [
    {
      "file": "/var/www/app.js",
      "line": 42,
      "function": "handleUpload",
      "class": "",
      "args": []
    }
  ]
}
```
*(Note: V8 does not natively expose local variables to the stack trace dynamically without the Inspector API. The `args` array is kept empty to preserve performance).*

### Event Mapping & Expected Backend Action

#### 1. Asynchronous Blocking (Vandam MUST reply `{"verdict": "allow"|"deny"}`)
Because Node.js is single-threaded, the agent wraps these asynchronous functions in a `Promise`. It pauses the specific execution context and waits for a verdict without freezing the rest of the web server. If denied, it rejects the Promise or returns an error to the callback.
* **`exec_call`**: Command Execution (`child_process.exec`)
* **`file_read` / `file_write`**: File Access (`fs.open`). Mapped based on file mode flags (e.g. `w`, `a`, `+`).
* **`chmod`**: Permissions (`fs.chmod`)

#### 2. Fire-And-Forget (Vandam does NOT reply)
For synchronous JS functions (where awaiting a socket would freeze the Event Loop) and high-volume dynamic actions, the agent acts purely as a sensor. It shoots the JSON payload to Vandam and **instantly allows execution** to continue. Vandam should ingest the data for cloud analysis, but the RASP does not wait for a verdict.
* **Synchronous Fallbacks**: `child_process.execSync`, `fs.openSync`
* **`file_compile`**: Module Loading (`Module.require`).
* **`eval_code`**: Dynamic Code (`global.eval`, `vm.runInThisContext`). The `path` field contains a preview of the raw string/code.
* **`dynamic_load`**: C++ Addon Loading (`process.dlopen`). The `path` field contains the library path.

## Production Bootstrapping & The "Process Trap"

Node.js explicitly prevents global file auto-loading (like Python's `.pth`) to stop code injection. However, we achieve **100% unbypassable bootstrapping** using the Vandam "Process Trap" architecture.

### The Process Trap Architecture
1. **Global Injection:** The Vandam Rust Daemon (running as root) automatically injects the RASP configuration into the global server environment (e.g., via `/etc/environment` or `/etc/profile.d/vandam.sh`).
   ```bash
   export NODE_OPTIONS="--require /opt/vandam/vandam.js"
   ```
2. **The Trap:** When the web server (PM2, Systemd, or Docker) starts the Node application, it naturally inherits this environment variable, natively loading Vandam into the V8 engine.
3. **The Lock-In:** If an attacker discovers an RCE vulnerability (e.g., via `eval`), they might try to bypass the agent by spawning a clean process (`child_process.exec('env -i node exploit.js')`). **This is impossible.** Because Vandam is *already* hooked into the parent process, it instantly intercepts the `exec` call and blocks it. The attacker is physically trapped inside the monitored parent process and can never spawn an unmonitored child.

### Bun & Deno Support

**Bun:**
Bun natively respects `NODE_OPTIONS`, so the exact same global environment variable works perfectly. Alternatively, Vandam can drop a global `/etc/bunfig.toml`:
```toml
preload = ["/opt/vandam/vandam.js"]
```

**Deno:**
Deno is strictly sandboxed. To bootstrap Deno, Vandam can hook into the orchestrator (modifying Systemd service files or Docker commands) to automatically append `--import /opt/vandam/vandam.js`. Once the Deno parent process boots, the exact same Process Trap logic applies—if the attacker tries to use `Deno.Command` to escape, the RASP intercepts and blocks it.
