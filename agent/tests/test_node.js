console.log("Loading Node RASP Agent...");
require(require('path').join(__dirname, '..', '..', 'integrations', 'node', 'vandam.js'));

setTimeout(() => {
    console.log("\n--- Triggering RASP Events ---");
    
    console.log("1. Testing exec_call (child_process.execSync)...");
    const cp = require('child_process');
    try { cp.execSync("echo 'Hello from Node'"); } catch(e){}

    console.log("2. Testing eval_code (eval)...");
    try { eval("1+1"); } catch(e){}

    console.log("3. Testing file_read (fs.readFileSync)...");
    const fs = require('fs');
    try { fs.readFileSync("/etc/passwd"); } catch(e){}

    console.log("4. Testing dynamic_load (process.dlopen)...");
    try { process.dlopen({exports:{}}, "libc.so.6"); } catch(e){}

    console.log("Node test complete.");
    
    setTimeout(() => { process.exit(0); }, 1000); // Flush queues
}, 1000);
