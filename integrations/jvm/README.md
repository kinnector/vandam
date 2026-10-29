# Vandam JVM Hybrid Agent

The Vandam JVM Agent is a dual-architecture agent designed to comprehensively secure the Java Virtual Machine. It combines a **Native C++ JVMTI Agent** with a **Pure Java ByteBuddy Agent (`-javaagent`)** to provide total coverage across memory, network, and execution layers.

## Architecture

1. **The C++ JVMTI Agent (`vandam-jvm.so`)**
   - **TLS Decryption:** Intercepts JSSE `read()` and `write()` methods in memory to extract decrypted plaintext TLS buffers directly to Vandam's forensic ring buffer.
   - **Class Memory Scanning:** Uses `ClassFileLoadHook` to scan raw byte arrays for exploits (e.g., Ysoserial payload chains, in-memory Web Shells) before the class is ever loaded into the JVM.

2. **The Java RASP Agent (`rasp-agent/vandam-java.jar`)**
   - Uses ByteBuddy to natively rewrite the bytecode of the JVM Standard Library (`java.base`).
   - **Command Execution:** Intercepts `ProcessBuilder.start()`.
   - **File Access:** Intercepts `FileInputStream` and `FileOutputStream`.
   - **Native Code:** Intercepts `Runtime.loadLibrary()` to catch malicious `.so`/`.dll` drops.

## Telemetry
- **JVMTI Agent:** Sends high-throughput binary structs to `/var/run/kinnector/tls_telemetry.sock`.
- **Java RASP Agent:** Sends identical JSON payloads to `/run/vandam/rasp_telemetry.sock` (same as Python, Node, PHP).

## Build Instructions

### 1. Build the C++ JVMTI Agent
```bash
mkdir -p build && cd build
cmake ..
make
```

### 2. Build the Java RASP Agent
```bash
cd rasp-agent
mvn clean package
```

## Production Bootstrapping
The Vandam Daemon entirely abstracts the installation process. It injects the global environment variable `JAVA_TOOL_OPTIONS` into the Linux server's environment:

```bash
export JAVA_TOOL_OPTIONS="-agentpath:/opt/vandam/vandam-jvm.so -javaagent:/opt/vandam/vandam-java.jar"
```

**The Result:** Every single Java application (Spring Boot, Tomcat, Scala, etc.) on the server automatically boots both agents sequentially. Zero application code modifications are required.

