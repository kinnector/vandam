import sys
import os
import time

print("Loading Vandam RASP Agent...")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'integrations', 'python'))
import vandam

# Wait for control socket to activate the agent
time.sleep(1)

print("\n--- Triggering RASP Events ---")
print("1. Testing exec_call (os.system)...")
os.system("echo 'Hello from Python'")

print("2. Testing eval_code (eval)...")
eval("1 + 1")

print("3. Testing eval_code (exec)...")
exec("x = 2 + 2")

print("4. Testing file_read (open /etc/passwd)...")
try:
    with open("/etc/passwd", "r") as f:
        f.read(10)
except Exception:
    pass

print("5. Testing dynamic_load (ctypes.CDLL)...")
try:
    import ctypes
    ctypes.CDLL("libc.so.6")
except Exception:
    pass

print("Python test complete.")
time.sleep(1) # Flush queues
