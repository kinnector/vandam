# Vandam Python RASP Agent

The Vandam Python RASP Agent uses native PEP 578 Audit Hooks to intercept dangerous OS-level calls, file system modifications, imports, and FFI bypasses deep inside the Python C-runtime.

## JSON Telemetry Schema & Mapping
The agent sends JSON payloads to `/run/vandam/rasp_telemetry.sock`. The Vandam backend must be ready to ingest this structure.

```json
{
  "type": "exec_call",
  "pid": 12345,
  "function": "os.system",
  "path": "whoami",
  "in_request": 0,
  "http": {},
  "trace": [
    {
      "file": "/var/www/app.py",
      "line": 42,
      "function": "handle_upload",
      "class": "",
      "args": ["user_input='whoami'"]
    }
  ]
}
```

### Event Mapping & Expected Backend Action

#### 1. Synchronous Blocking (Vandam MUST reply `{"verdict": "allow"|"deny"}`)
The agent halts the Python thread and waits for up to 0.5 seconds for a verdict. If denied, it throws `PermissionError`.
* **`exec_call`**: Command Execution (`os.system`, `subprocess.Popen`)
* **`file_read` / `file_write`**: File Access (`open()`). Mapped based on file mode flags (e.g. `w`, `a`, `+`).
* **`chmod`**: Permissions (`os.chmod`)

#### 2. Fire-And-Forget (Vandam does NOT reply)
The agent sends the JSON payload and instantly allows Python to continue. Vandam should ingest the data for cloud analysis or logging, but the RASP does not wait for a verdict.
* **`file_compile`**: Magic Loading & Imports (`import`). Sent when a `.py` or `.so` is natively imported into memory.
* **`eval_code`**: Dynamic Code (`eval()`, `exec`, `compile`). The `path` field contains the raw injected string/code.
* **`dynamic_load`**: C-Library Loading (`ctypes.dlopen`, `ctypes.dlsym`, `ctypes.call_function`). The `path` field contains the library or symbol being accessed.

## Installation
See the `.pth` installation documentation for bootstrapping the agent system-wide.
