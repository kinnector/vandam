<?php
echo "Loading PHP RASP Agent...\n";
// The extension should be loaded via php -d extension=...

sleep(1); // Wait for mock daemon connection (if needed)

echo "\n--- Triggering RASP Events ---\n";
echo "1. Testing exec_call (system)...\n";
system("echo 'Hello from PHP'");

echo "2. Testing eval_code (eval)...\n";
eval("1 + 1;");

echo "3. Testing file_read (file_get_contents)...\n";
@file_get_contents("/etc/passwd");

echo "4. Testing dynamic_load (ffi)...\n";
try {
    $ffi = FFI::cdef("void *dlopen(const char *filename, int flag);", "libc.so.6");
    $ffi->dlopen("libc.so.6", 1);
} catch (Exception $e) {}

echo "PHP test complete.\n";
sleep(1);
