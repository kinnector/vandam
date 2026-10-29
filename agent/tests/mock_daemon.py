import socket
import os
import json
import threading
import sys

SOCKETS = [
    "/run/vandam/rasp.sock",
    "/run/vandam/rasp_telemetry.sock",
    "/run/vandam/rasp_control.sock"
]

TCP_SOCKETS = [
    (45300, False, False), # Blocking
    (45301, True, False),  # Telemetry
    (45302, False, True)   # Control
]

def handle_client(conn, is_telemetry, is_control):
    if is_control:
        # Immediately activate any agent connecting to the control socket
        print("[CONTROL] Agent connected, sending activation command.")
        conn.sendall(b'{"action":"activate","mode":"block"}\n')

    while True:
        try:
            data = conn.recv(65536)
            if not data:
                break
            
            lines = data.decode('utf-8').strip().split('\n')
            for line in lines:
                if not line: continue
                try:
                    payload = json.loads(line)
                    print(f"[{'TELEMETRY' if is_telemetry else ('CONTROL' if is_control else 'BLOCKING')}] Type: {payload.get('type')} | Func: {payload.get('function', '')} | InstallContext: {payload.get('is_install_context', 0)}")
                    if not is_telemetry and not is_control:
                        # Respond to blocking requests
                        # Let's say block /etc/passwd just to show it blocks
                        path = payload.get("path", "")
                        if "passwd" in path:
                            conn.sendall(b'{"verdict":"deny","incident_id":"MOCK-123"}\n')
                        else:
                            conn.sendall(b'{"verdict":"allow"}\n')
                except Exception as e:
                    print(f"Error parsing JSON: {e}")
        except Exception:
            break
    conn.close()

def start_unix_server(sock_path, is_telemetry, is_control):
    if os.path.exists(sock_path):
        os.remove(sock_path)
    
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    os.chmod(sock_path, 0o777)
    server.listen(100)
    print(f"Listening on UNIX {sock_path}...")
    
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle_client, args=(conn, is_telemetry, is_control)).start()

def start_tcp_server(port, is_telemetry, is_control):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', port))
    server.listen(100)
    print(f"Listening on TCP 127.0.0.1:{port}...")
    
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle_client, args=(conn, is_telemetry, is_control)).start()


if __name__ == "__main__":
    print("Starting Universal Mock Vandam Daemon...")
    try:
        os.makedirs("/run/vandam", exist_ok=True)
        os.chmod("/run/vandam", 0o777)
    except PermissionError:
        print("ERROR: Run with sudo! (Need permission to create /run/vandam)")
        sys.exit(1)
    
    for sock_path in SOCKETS:
        is_telemetry = "telemetry" in sock_path
        is_control = "control" in sock_path
        threading.Thread(target=start_unix_server, args=(sock_path, is_telemetry, is_control), daemon=True).start()
        
    for port, is_telemetry, is_control in TCP_SOCKETS:
        threading.Thread(target=start_tcp_server, args=(port, is_telemetry, is_control), daemon=True).start()

    print("Mock Daemon is live. Waiting for test agents to send events...")
    try:
        import time
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down.")
