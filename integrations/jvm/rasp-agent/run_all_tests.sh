#!/bin/bash
# Runs Test.java under the RASP agent on Java 8, 17 and the default JDK against the mock daemon.
# Build the agent first (mvn package). The mock daemon binds the agent's socket, so it runs under
# sudo, which asks for a password once.
set -e

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
cd "$here"

echo "Compiling Test.java..."
javac -source 1.8 -target 1.8 Test.java

echo "Starting Mock Daemon in background..."
sudo python3 -u "$repo/agent/tests/mock_daemon.py" > daemon_output.log 2>&1 &
DAEMON_PID=$!
sleep 2 # wait for daemon to start

run_test() {
    JAVA_BIN=$1
    echo ""
    echo "==========================================="
    echo "Testing with $JAVA_BIN"
    echo "==========================================="
    $JAVA_BIN -javaagent:"$here/target/vandam-java-1.0-SNAPSHOT.jar" -cp "$here" Test
    echo "Waiting for telemetry..."
    sleep 1
}

run_test "/usr/lib/jvm/java-8-openjdk-amd64/bin/java"
run_test "/usr/lib/jvm/java-17-openjdk-amd64/bin/java"
run_test "java" # Java 21 is default

echo ""
echo "Killing daemon..."
sudo kill $DAEMON_PID || true

echo ""
echo "==========================================="
echo "MOCK DAEMON OUTPUT:"
echo "==========================================="
cat daemon_output.log
