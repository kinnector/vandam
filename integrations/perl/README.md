# Vandam Perl RASP Agent

The Vandam Perl RASP Agent is a native C-Extension (XS module) that hooks directly into the Perl Opcode Compilation Tree (`PL_check`), intercepting exploits at the lowest possible engine level before they execute.

## Interception Coverage

### 1. Opcode Hooking (C-Level)
**Covered:** Yes.
Unlike standard APMs that use `CORE::GLOBAL` overrides (which can be bypassed or broken by complex prototypes), Vandam hooks the actual `op_ppaddr` function pointers inside the Perl execution loop. This means it is physically impossible for userland Perl code to bypass the RASP or un-patch it.

### 2. Magic Loading & Imports
**Covered:** Yes.
We inject a custom CodeRef into the very beginning of the `@INC` array. Whenever Perl attempts to `use Module` or `require 'file.pl'`, our CodeRef intercepts the exact filename being requested, shoots telemetry to Vandam, and then instructs the Perl engine to continue loading it normally.

## JSON Telemetry Schema & Mapping
The agent sends JSON payloads to `/run/vandam/rasp_telemetry.sock`. The Vandam backend must be ready to ingest this exact structure.

```json
{
  "type": "exec_call",
  "pid": 12345,
  "function": "system",
  "path": "whoami",
  "in_request": 0,
  "http": {},
  "trace": [
    {
      "file": "/var/www/cgi-bin/app.cgi",
      "line": 42,
      "function": "handle_upload",
      "class": "main",
      "args": []
    }
  ]
}
```

### Event Mapping & Expected Backend Action

#### 1. Synchronous Blocking (Vandam MUST reply `{"verdict": "allow"|"deny"}`)
The native C-extension halts the Perl execution loop and waits for up to 0.5 seconds for a verdict using `select()`. If denied, it throws a fatal C-level `croak()`, instantly killing the script.
* **`exec_call`**: OS Commands (Intercepted via `OP_SYSTEM`, `OP_EXEC`, and `OP_BACKTICK`)

#### 2. Fire-And-Forget (Vandam does NOT reply)
The C-extension shoots the JSON payload to Vandam and instantly allows execution to continue.
* **`file_compile`**: Module Loads (`require`, `use`). Intercepted via `@INC` hooks.
* **`eval_code`**: String execution (`eval "code"`). Intercepted natively via `OP_ENTEREVAL`. The `path` field contains a preview of the raw string extracted directly from the C-Stack.

## Installation
Compile the XS module natively:
```bash
perl Makefile.PL
make
sudo make install
```

## Production Bootstrapping (Engine Lock)
To install the agent universally across all Perl CGI scripts and background workers without editing any code, we lock it directly into the Perl engine's boot sequence.

Perl natively evaluates a global system file called `sitecustomize.pl` before executing any user script.
1. The Vandam Daemon installer locates the system's `sitecustomize.pl` (typically in `/etc/perl/` or `/usr/local/lib/perl5/`).
2. It appends the following line:
   ```perl
   use Vandam;
   ```

**The Result:** Every single Perl process on the entire server natively boots the RASP C-Extension before user code is parsed. It cannot be bypassed by unsetting environment variables or using clean execution shells (`env -i`).
