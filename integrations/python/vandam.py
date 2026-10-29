import sys
import os
import socket
import json
import traceback
import threading

VANDAM_TELEMETRY_SOCKET = "/run/vandam/rasp_telemetry.sock"
VANDAM_CONTROL_SOCKET = "/run/vandam/rasp_control.sock"

# Global toggle controlled by Vandam Rust Daemon
IS_ACTIVATED = False

# Cache verdicts to prevent socket spam (e.g. {"os.system:ls": "deny", "open:/tmp/foo": "allow"})
VERDICT_CACHE = {}

# Decoupled cache specifically for fire-and-forget one-time telemetry
TELEMETRY_CACHE = set()

IS_INSTALL_CONTEXT = 1 if (
    "pip" in sys.argv[0] or 
    "setup.py" in sys.argv[0] or 
    "easy_install" in sys.argv[0]
) else 0

def get_traceback_with_locals():
    """Walks the Python frame stack to extract the traceback and local variables."""
    formatted_trace = []
    try:
        # Start at 2 to skip this function and the hook itself
        f = sys._getframe(2)
        while f:
            local_vars = []
            for k, v in f.f_locals.items():
                if isinstance(v, (str, int, float, bool)):
                    val_str = str(v)
                    if len(val_str) > 100:
                        val_str = val_str[:97] + "..."
                    local_vars.append(f"{k}={val_str}")
                elif v is None:
                    local_vars.append(f"{k}=None")
                else:
                    local_vars.append(f"{k}=[{type(v).__name__}]")

            formatted_trace.append({
                "file": f.f_code.co_filename,
                "line": f.f_lineno,
                "function": f.f_code.co_name,
                "class": "",
                "args": local_vars
            })
            f = f.f_back
    except Exception:
        pass
    
def vandam_audit_hook(event, args):
    """
    Native PEP 578 Audit Hook.
    """
    # ZERO OVERHEAD: If Vandam hasn't explicitly activated us, return instantly.
    if not IS_ACTIVATED:
        return

    # Monitor Command Execution, File System access, Permissions, FFI/Ctypes, and Imports/Eval
    if event not in ("os.system", "subprocess.Popen", "open", "os.chmod", "ctypes.dlopen", "ctypes.dlsym", "ctypes.call_function", "import", "exec", "compile"):
        return

    command = ""
    if args:
        if event == "open" and len(args) > 1:
            command = f"{args[0]} (Mode: {args[1]})"
        elif event == "os.chmod" and len(args) > 1:
            command = f"{args[0]} (Perms: {oct(args[1])})"
        elif event == "ctypes.dlopen":
            command = f"Library: {args[0]}"
        elif event == "ctypes.dlsym" and len(args) > 1:
            command = f"Library: {args[0]}, Symbol: {args[1]}"
        else:
            command = str(args[0])

    # Semantic mapping to unify Python and PHP telemetry types
    event_type = "exec_call"
    if event == "open":
        event_type = "file_write" if "w" in command or "+" in command or "a" in command else "file_read"
    elif event == "os.chmod":
        event_type = "chmod"
    elif event == "import":
        event_type = "file_compile"
    elif event in ("exec", "compile"):
        event_type = "eval_code"
    elif event.startswith("ctypes."):
        event_type = "dynamic_load"

    # Measure total payload size before truncation
    command_str = str(command)
    payload_size_bytes = len(command_str)

    # 1. Hard Cap for dynamic code evaluation (2MB)
    if event in ("exec", "compile") and payload_size_bytes > 2097152:
        raise PermissionError(f"Vandam RASP blocked execution: Payload exceeded 2MB hard cap ({payload_size_bytes} bytes).")

    # 2. Head + Tail Truncation for oversized strings (>4KB)
    if payload_size_bytes > 4096:
        command_str = command_str[:2048] + "\n...[TRUNCATED_MIDDLE]...\n" + command_str[-2048:]
    command = command_str

    cache_key = f"{event}:{command}"
    is_fire_and_forget = event.startswith("ctypes.") or event in ("import", "exec", "compile")

    if not is_fire_and_forget:
        cached_verdict = VERDICT_CACHE.get(cache_key)
        if cached_verdict:
            if cached_verdict == "deny":
                raise PermissionError(f"Vandam RASP blocked execution of '{event}' (Cached)")
            return # Allowed

    payload = {
        "type": event_type,
        "pid": os.getpid(),
        "function": event,
        "path": command,
        "payload_size_bytes": payload_size_bytes,
        "in_request": 0,
        "http": {},
        "trace": [],
        "is_install_context": IS_INSTALL_CONTEXT
    }
    
    # Fast-path for FFI/ctypes and Imports/Eval: Pure telemetry, no blocking verdicts
    if is_fire_and_forget:
        try:
            f = sys._getframe(1)
            top_frame = f"{f.f_code.co_filename}:{f.f_lineno}"
        except Exception:
            top_frame = "unknown:0"
            
        trace_cache_key = f"trace:{event}:{top_frame}"
        
        if trace_cache_key in TELEMETRY_CACHE:
            payload["trace"] = []
        else:
            payload["trace"] = get_traceback_with_locals()
            if len(TELEMETRY_CACHE) > 1000:
                TELEMETRY_CACHE.clear()
            TELEMETRY_CACHE.add(trace_cache_key)
            
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.1) 
                sock.connect(VANDAM_TELEMETRY_SOCKET)
                sock.sendall((json.dumps(payload) + "\n").encode('utf-8'))
        except Exception:
            pass
        return

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5) 
            sock.connect(VANDAM_TELEMETRY_SOCKET)
            sock.sendall((json.dumps(payload) + "\n").encode('utf-8'))
            
            response = sock.recv(1024).decode('utf-8').strip()
            if response:
                data = json.loads(response)
                verdict = data.get("verdict", "allow")
                incident_id = data.get("incident_id")
                
                if len(VERDICT_CACHE) > 1000:
                    VERDICT_CACHE.clear()
                VERDICT_CACHE[cache_key] = verdict
                
                if verdict == "deny":
                    if incident_id:
                        trace_payload = {"incident_id": incident_id, "trace": get_traceback_with_locals()}
                        try:
                            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as tsock:
                                tsock.settimeout(0.1)
                                tsock.connect(VANDAM_TELEMETRY_SOCKET)
                                tsock.sendall((json.dumps(trace_payload) + "\n").encode('utf-8'))
                        except Exception:
                            pass
                    raise PermissionError(f"Vandam RASP blocked execution of '{event}'")
            else:
                if len(VERDICT_CACHE) > 1000:
                    VERDICT_CACHE.clear()
                VERDICT_CACHE[cache_key] = "allow" # Fail-open cache
    except PermissionError:
        raise
    except Exception:
        # Fail-open if socket is down, do NOT cache so it can recover later
        pass

def vandam_activation_listener():
    """
    Background thread that connects to Vandam and waits for instructions.
    """
    global IS_ACTIVATED
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(VANDAM_CONTROL_SOCKET)
            
            # Announce our PID to Vandam
            handshake = {"type": "hello", "pid": os.getpid()}
            sock.sendall((json.dumps(handshake) + "\n").encode('utf-8'))
            
            # Wait for Vandam to send 'activate' or 'deactivate'
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                    
                msg = json.loads(data.decode('utf-8').strip())
                if msg.get("action") == "activate":
                    IS_ACTIVATED = True
                elif msg.get("action") == "deactivate":
                    IS_ACTIVATED = False
    except Exception:
        pass # If Vandam isn't running, we silently die and stay deactivated

# Bootstrap the RASP Agent
try:
    sys.addaudithook(vandam_audit_hook)
    
    # Spawn the listener as a Daemon thread so it won't block Python from exiting
    listener = threading.Thread(target=vandam_activation_listener, daemon=True)
    listener.start()
except Exception:
    pass
