# Vandam Java RASP Agent

The Vandam Java RASP Agent is a native JVM Bytecode Interceptor (`-javaagent`). It uses the ByteBuddy library to manipulate the bytecode of the Java Standard Library (`java.base`) *before* classes are loaded into the JVM.

## Interception Coverage

### 1. Opcode Hooking (Bytecode Level)
**Covered:** Yes.
Unlike intercepting at the application level (e.g. Spring interceptors), Vandam rewrites the actual bytecode of core JVM classes like `ProcessBuilder` and `FileInputStream`. It is mathematically impossible for any Java code, library, or framework to bypass this, because the underlying JVM execution path has been permanently altered.

### 2. Command Execution
**Covered:** Yes.
We intercept `java.lang.ProcessBuilder.start()`. Because `Runtime.getRuntime().exec()` internally routes through `ProcessBuilder` in modern Java, we catch all OS command executions natively.

### 3. File Reads and Writes
**Covered:** Yes.
We intercept the constructors of `java.io.FileInputStream` and `java.io.FileOutputStream`.

### 4. JNI / Native Code (C/C++ Extensions)
**Covered:** Yes.
We intercept `Runtime.loadLibrary0` and `Runtime.load0`. If an attacker attempts to drop a native `.so` or `.dll` payload to bypass the JVM entirely, we capture the library path natively.

## JSON Telemetry Schema & Mapping
The agent sends JSON payloads to `/run/vandam/php_telemetry.sock`. Because it uses Java 16+ `UnixDomainSocketAddress`, it achieves microsecond latency communicating with the Rust Daemon.

```json
{
  "type": "exec_call",
  "pid": 12345,
  "function": "ProcessBuilder.start",
  "path": "whoami",
  "in_request": 0,
  "http": {},
  "trace": [
    {
      "file": "Application.java",
      "line": 42,
      "function": "executeCommand",
      "class": "com.company.Application",
      "args": []
    }
  ]
}
```

### Event Mapping & Expected Backend Action

#### 1. Synchronous Blocking (Vandam MUST reply `{"verdict": "allow"|"deny"}`)
The Java thread pauses and awaits a socket response. If denied, it throws a `SecurityException`.
* **`exec_call`**: OS Commands (`ProcessBuilder.start`)
* **`file_read`**: File Reads (`FileInputStream`)
* **`file_write`**: File Writes (`FileOutputStream`)

#### 2. Fire-And-Forget (Vandam does NOT reply)
* **`dynamic_load`**: JNI Loading (`Runtime.loadLibrary`). Sent asynchronously to prevent freezing.

## Building
```bash
mvn clean package
```
This produces `target/vandam-java-1.0-SNAPSHOT.jar` (a fat JAR containing ByteBuddy and the premain manifest).

## Production Bootstrapping
To install the agent universally across all Java applications (Spring Boot, Tomcat, WildFly, Scala, Kotlin, etc.), the Vandam Daemon injects the `-javaagent` flag into the global environment variable `JAVA_TOOL_OPTIONS`.

```bash
export JAVA_TOOL_OPTIONS="-javaagent:/opt/vandam/vandam-java.jar"
```
The JVM natively checks this environment variable on boot and physically locks the RASP agent into the engine before the application even starts.
