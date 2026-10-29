# Vandam Ruby RASP Agent

The Vandam Ruby RASP Agent leverages Ruby's native metaprogramming capabilities (`Module#prepend` and `alias_method`) to comprehensively wrap the core standard library, intercepting dangerous operations entirely from userland with zero C-compilation required.

## Interception Coverage

### 1. Magic Loading & Imports
**Covered:** Yes.
We intercept `Kernel.require` and `Kernel.load`. Any auto-loading frameworks (like Rails' Zeitwerk) rely on these primitives under the hood, meaning all auto-loaded classes and components are intercepted instantly.

### 2. C-Library Loading
**Covered:** Yes.
We intercept `Fiddle.dlopen`, which is Ruby's standard library interface for loading dynamic C-extensions (`.so` or `.dylib`) at runtime.

## JSON Telemetry Schema & Mapping
The agent sends JSON payloads to `/run/vandam/rasp_telemetry.sock`.

```json
{
  "type": "exec_call",
  "pid": 12345,
  "function": "Kernel.system",
  "path": "whoami",
  "in_request": 0,
  "http": {},
  "trace": [
    {
      "file": "/var/www/app.rb",
      "line": 42,
      "function": "handle_upload",
      "class": "",
      "args": []
    }
  ]
}
```

### Event Mapping & Expected Backend Action

#### 1. Synchronous Blocking (Vandam MUST reply `{"verdict": "allow"|"deny"}`)
The agent halts the Ruby thread and waits for up to 0.5 seconds for a verdict using `IO.select`. If denied, it throws a standard `SecurityError`, halting the application cleanly.
* **`exec_call`**: OS Commands (`Kernel.system`, `Kernel.exec`, ``` Kernel.` ```)
* **`file_read` / `file_write`**: File Access (`File.open`). Mapped based on file mode flags.
* **`chmod`**: Permission changes (`File.chmod`)

#### 2. Fire-And-Forget (Vandam does NOT reply)
For high-volume dynamic actions, the agent acts purely as a sensor. It shoots the JSON payload to Vandam and **instantly allows execution** to continue. Vandam must ingest this telemetry, but any allow/deny replies are ignored.
* **`file_compile`**: File Imports (`require`, `load`)
* **`eval_code`**: Dynamic Code Execution (`eval`, `instance_eval`, `class_eval`). The `path` field contains a preview of the raw injected string.
* **`dynamic_load`**: C-Library Loading (`Fiddle.dlopen`)

## Production Bootstrapping (Unbypassable)
To install the agent universally across the entire operating system, we hook directly into the Ruby engine's boot sequence.

1. Open your system's global `operating_system.rb` (usually located at `/usr/lib/ruby/vendor_ruby/rubygems/defaults/operating_system.rb`).
2. Append the following line:
   ```ruby
   require '/opt/vandam/vandam.rb'
   ```
This guarantees that **every** Ruby process on the server loads the RASP agent natively, regardless of user environment variables.
