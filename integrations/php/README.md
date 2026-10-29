# Vandam PHP RASP Agent

The Vandam PHP RASP Agent is a native C extension that hooks directly into the Zend Engine's function and compilation tables to intercept exploits natively.

## JSON Telemetry Schema & Mapping
The agent sends JSON payloads to `/run/vandam/rasp_telemetry.sock`. The Vandam backend must be ready to ingest this exact structure.

```json
{
  "type": "exec_call",
  "pid": 12345,
  "function": "system",
  "path": "whoami",
  "in_request": 1,
  "http": {
    "method": "POST",
    "uri": "/upload.php",
    "query": "id=1",
    "remote_addr": "192.168.1.100",
    "http_host": "example.com",
    "_SERVER": {"HTTP_USER_AGENT": "curl/7.68.0"},
    "_POST": {"payload": "whoami"},
    "_GET": {"id": "1"},
    "_FILES": {},
    "_COOKIE": {}
  },
  "trace": [
    {
      "file": "/var/www/upload.php",
      "line": 42,
      "function": "handle_upload",
      "class": "Uploader",
      "args": ["\"whoami\""]
    }
  ]
}
```
*(Note: If `in_request` is 0 (e.g. CLI scripts), the `http` object fields will be empty strings or `{}`).*

### Event Mapping & Expected Backend Action

#### 1. Synchronous Blocking (Vandam MUST reply `{"verdict": "allow"|"deny"}`)
The C-extension halts the Zend Engine thread and waits for up to 0.5 seconds for a verdict. If denied, it natively aborts the PHP function, preventing the syscall.
* **`exec_call`**: OS Command Execution (`exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`, `pcntl_exec`)
* **`file_read`**: File Reads (`fopen` [read mode], `file_get_contents`, `readfile`)
* **`file_write`**: File Writes (`fopen` [write mode], `file_put_contents`)
* **`chmod`**: Permission changes (`chmod`)

#### 2. Fire-And-Forget (Vandam does NOT reply)
The agent shoots the JSON payload to Vandam and instantly allows the Zend Engine to continue. There is zero blocking latency. Vandam must ingest this telemetry, but any `allow/deny` replies are ignored.
* **`file_compile`**: Magic Loading & Includes (`include`, `require`, `spl_autoload`). Emitted when `zend_compile_file` evaluates a file.
* **`eval_code`**: Dynamic Code Execution (`eval`, `assert`, `create_function`). Emitted when `zend_compile_string` compiles a raw string. The `path` field contains a preview of the raw injected code.
* **`dynamic_load`**: C-Library Loading (`dl()`). Emitted when an `.so` extension is loaded dynamically.
* **`ffi_call`**: Foreign Function Interfaces (reserved for `FFI::cdef`).

## Installation
See the main guide for compiling with `phpize` and enabling via `extension=vandam_php.so`.
