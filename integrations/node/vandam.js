const net = require('net');
const fs = require('fs');
const child_process = require('child_process');
const vm = require('vm');
const Module = require('module');

const VANDAM_TELEMETRY_SOCKET = '/run/vandam/rasp_telemetry.sock';
const VANDAM_CONTROL_SOCKET = '/run/vandam/rasp_control.sock';

const ua = (process.env.npm_config_user_agent || '').toLowerCase();
const argvStr = process.argv.join(' ').toLowerCase();

const isNpmCompat = !!(process.env.npm_lifecycle_event || process.env.npm_config_argv || process.env.npm_package_name);
const isPnpm = ua.includes('pnpm') || !!process.env.PNPM_SCRIPT_SRC_DIR;
const isBun = ua.includes('bun') || !!process.env.BUN_INSTALL_BIN || argvStr.includes('bun install') || argvStr.includes('bun add');
const isYarn = ua.includes('yarn') || !!process.env.YARN_WRAP_OUTPUT || argvStr.includes('yarn install') || argvStr.includes('yarn add');
const isDeno = ua.includes('deno') || argvStr.includes('deno install') || argvStr.includes('deno cache');

const IS_INSTALL_CONTEXT = (isNpmCompat || isPnpm || isBun || isYarn || isDeno) ? 1 : 0;

let IS_ACTIVATED = false;
const VERDICT_CACHE = new Map();
const TELEMETRY_CACHE = new Set();
let persistentSocket = null;

function getPersistentSocket() {
    if (persistentSocket && !persistentSocket.destroyed) {
        return persistentSocket;
    }
    persistentSocket = net.createConnection({ path: VANDAM_TELEMETRY_SOCKET });
    persistentSocket.on('error', () => { if (persistentSocket) persistentSocket.destroy(); });
    persistentSocket.unref(); // Prevent socket from blocking event loop exit
    return persistentSocket;
}

function preparePayload(type, path) {
    let pathStr = String(path);
    const payload_size_bytes = pathStr.length;
    
    if ((type === 'eval_code' || type === 'file_compile') && payload_size_bytes > 2097152) {
        throw new Error(`Vandam RASP blocked execution: Payload exceeded 2MB hard cap (${payload_size_bytes} bytes).`);
    }

    if (payload_size_bytes > 4096) {
        pathStr = pathStr.substring(0, 2048) + "\n...[TRUNCATED_MIDDLE]...\n" + pathStr.substring(payload_size_bytes - 2048);
    }
    return { pathStr, payload_size_bytes };
}

function getTraceback() {
    const stack = new Error().stack.split('\n').slice(3);
    const formattedTrace = [];
    for (const line of stack) {
        const match = line.match(/at (.*?) \((.*?):(\d+):(\d+)\)/) || line.match(/at (.*?):(\d+):(\d+)/);
        if (match) {
            formattedTrace.push({
                file: match[2] || match[1],
                line: parseInt(match[3] || match[2], 10),
                function: match[4] ? match[1] : 'anonymous',
                class: "",
                args: [] // Local variables ignored per design
            });
        }
    }
    return formattedTrace.reverse();
}

function sendFireAndForget(type, func, path) {
    if (!IS_ACTIVATED) return;
    try {
        const { pathStr, payload_size_bytes } = preparePayload(type, path);
        let topFrame = "unknown:0";
        const oldLimit = Error.stackTraceLimit;
        Error.stackTraceLimit = 3;
        const stackObj = {};
        Error.captureStackTrace(stackObj);
        if (stackObj.stack) {
            const stackLines = stackObj.stack.split('\n');
            if (stackLines.length > 2) topFrame = stackLines[2].trim();
        }
        Error.stackTraceLimit = oldLimit;
        const traceCacheKey = `trace:${func}:${topFrame}`;
        
        const payload = {
            type: type,
            pid: process.pid,
            function: func,
            path: pathStr,
            payload_size_bytes: payload_size_bytes,
            in_request: 0,
            http: {},
            trace: [],
            is_install_context: IS_INSTALL_CONTEXT
        };
        
        if (!TELEMETRY_CACHE.has(traceCacheKey)) {
            payload.trace = getTraceback();
            if (TELEMETRY_CACHE.size > 1000) TELEMETRY_CACHE.clear();
            TELEMETRY_CACHE.add(traceCacheKey);
        }
        
        const client = getPersistentSocket();
        client.write(JSON.stringify(payload) + "\n");
    } catch(e) {
        if (e.message.includes('hard cap')) throw e;
    }
}

function askVandamAsync(type, func, path) {
    if (!IS_ACTIVATED) return Promise.resolve();
    
    let prep;
    try {
        prep = preparePayload(type, path);
    } catch (e) {
        return Promise.reject(e);
    }
    const cacheKey = `${func}:${pathStr}`;
    
    if (VERDICT_CACHE.has(cacheKey)) {
        if (VERDICT_CACHE.get(cacheKey) === 'deny') {
            return Promise.reject(new Error(`Vandam RASP blocked execution of '${func}' (Cached)`));
        }
        return Promise.resolve();
    }

    return new Promise((resolve, reject) => {
        const payload = {
            type: type,
            pid: process.pid,
            function: func,
            path: pathStr,
            payload_size_bytes: payload_size_bytes,
            in_request: 0,
            http: {},
            trace: [],
            is_install_context: IS_INSTALL_CONTEXT
        };

        const client = net.createConnection({ path: VANDAM_TELEMETRY_SOCKET }, () => {
            client.write(JSON.stringify(payload) + "\n");
        });

        client.on('data', (data) => {
            try {
                const response = JSON.parse(data.toString().trim());
                const verdict = response.verdict || 'allow';
                const incident_id = response.incident_id;
                
                if (VERDICT_CACHE.size > 1000) VERDICT_CACHE.clear();
                VERDICT_CACHE.set(cacheKey, verdict);
                
                if (verdict === 'deny') {
                    if (incident_id) {
                        try {
                            const tracePayload = { incident_id: incident_id, trace: getTraceback() };
                            const tclient = net.createConnection({ path: VANDAM_TELEMETRY_SOCKET }, () => {
                                tclient.write(JSON.stringify(tracePayload) + "\n");
                                tclient.end();
                            });
                            tclient.on('error', () => {});
                        } catch(e) {}
                    }
                    reject(new Error(`Vandam RASP blocked execution of '${func}'`));
                } else {
                    resolve();
                }
            } catch (err) {
                resolve(); // Fail-open
            }
            client.end();
        });

        client.on('error', () => resolve()); // Fail-open
        setTimeout(() => { client.destroy(); resolve(); }, 500);
    });
}

function askVandamSync(type, func, path) {
    if (!IS_ACTIVATED) return;
    
    const { pathStr } = preparePayload(type, path);
    const cacheKey = `${func}:${pathStr}`;
    
    if (VERDICT_CACHE.has(cacheKey)) {
        if (VERDICT_CACHE.get(cacheKey) === 'deny') {
            throw new Error(`Vandam RASP blocked execution of '${func}' (Cached)`);
        }
        return;
    }
    // Synchronous calls fallback to Fire-And-Forget to prevent Event Loop freezing
    sendFireAndForget(type, func, pathStr);
}

// Helper to prevent un-monkey-patching (Anti-Tampering)
function freezeHook(obj, prop, newFunc) {
    Object.defineProperty(obj, prop, {
        value: newFunc,
        writable: false,
        configurable: false
    });
}

// ==========================================
// 1. COMMAND EXECUTION (EXHAUSTIVE)
// ==========================================
const originalExec = child_process.exec;
freezeHook(child_process, 'exec', function(command, options, callback) {
    if (!IS_ACTIVATED) return originalExec.apply(this, arguments);
    askVandamAsync('exec_call', 'child_process.exec', command)
        .then(() => originalExec.apply(this, arguments))
        .catch(err => {
            if (typeof callback === 'function') callback(err, "", "");
            else if (typeof options === 'function') options(err, "", "");
            else throw err;
        });
});

const originalSpawn = child_process.spawn;
freezeHook(child_process, 'spawn', function(command, args, options) {
    if (IS_ACTIVATED) askVandamSync('exec_call', 'child_process.spawn', `${command} ${args ? args.join(' ') : ''}`);
    return originalSpawn.apply(this, arguments);
});

const originalFork = child_process.fork;
freezeHook(child_process, 'fork', function(modulePath, args, options) {
    if (IS_ACTIVATED) askVandamSync('exec_call', 'child_process.fork', modulePath);
    return originalFork.apply(this, arguments);
});

const originalExecSync = child_process.execSync;
freezeHook(child_process, 'execSync', function(command, options) {
    if (IS_ACTIVATED) askVandamSync('exec_call', 'child_process.execSync', command);
    return originalExecSync.apply(this, arguments);
});


// ==========================================
// 2. FILE SYSTEM & PERMISSIONS (EXHAUSTIVE)
// ==========================================
const originalFsOpen = fs.open;
freezeHook(fs, 'open', function(path, flags, mode, callback) {
    if (!IS_ACTIVATED) return originalFsOpen.apply(this, arguments);
    let type = 'file_read';
    if (String(flags).match(/w|a|\+/)) type = 'file_write';
    askVandamAsync(type, 'fs.open', `${path} (Flags: ${flags})`)
        .then(() => originalFsOpen.apply(this, arguments))
        .catch(err => {
            let cb = typeof callback === 'function' ? callback : (typeof mode === 'function' ? mode : null);
            if (cb) cb(err); else throw err;
        });
});

const originalFsReadFile = fs.readFile;
freezeHook(fs, 'readFile', function(path, options, callback) {
    if (!IS_ACTIVATED) return originalFsReadFile.apply(this, arguments);
    askVandamAsync('file_read', 'fs.readFile', path)
        .then(() => originalFsReadFile.apply(this, arguments))
        .catch(err => {
            let cb = typeof callback === 'function' ? callback : (typeof options === 'function' ? options : null);
            if (cb) cb(err); else throw err;
        });
});

const originalFsWriteFile = fs.writeFile;
freezeHook(fs, 'writeFile', function(file, data, options, callback) {
    if (!IS_ACTIVATED) return originalFsWriteFile.apply(this, arguments);
    askVandamAsync('file_write', 'fs.writeFile', file)
        .then(() => originalFsWriteFile.apply(this, arguments))
        .catch(err => {
            let cb = typeof callback === 'function' ? callback : (typeof options === 'function' ? options : null);
            if (cb) cb(err); else throw err;
        });
});

const originalFsPromisesReadFile = fs.promises.readFile;
freezeHook(fs.promises, 'readFile', async function(path, options) {
    if (IS_ACTIVATED) await askVandamAsync('file_read', 'fs.promises.readFile', path);
    return originalFsPromisesReadFile.apply(this, arguments);
});

const originalFsPromisesWriteFile = fs.promises.writeFile;
freezeHook(fs.promises, 'writeFile', async function(file, data, options) {
    if (IS_ACTIVATED) await askVandamAsync('file_write', 'fs.promises.writeFile', file);
    return originalFsPromisesWriteFile.apply(this, arguments);
});

const originalFsChmod = fs.chmod;
freezeHook(fs, 'chmod', function(path, mode, callback) {
    if (!IS_ACTIVATED) return originalFsChmod.apply(this, arguments);
    askVandamAsync('chmod', 'fs.chmod', `${path} (Perms: ${mode.toString(8)})`)
        .then(() => originalFsChmod.apply(this, arguments))
        .catch(err => {
            if (typeof callback === 'function') callback(err); else throw err;
        });
});

// ==========================================
// 3. MAGIC LOADING & IMPORTS
// ==========================================
const originalRequire = Module.prototype.require;
freezeHook(Module.prototype, 'require', function(id) {
    if (IS_ACTIVATED) sendFireAndForget('file_compile', 'require', id);
    return originalRequire.apply(this, arguments);
});


// ==========================================
// 4. DYNAMIC CODE (EVAL)
// ==========================================
const originalVmRunInThisContext = vm.runInThisContext;
freezeHook(vm, 'runInThisContext', function(code, options) {
    if (IS_ACTIVATED) sendFireAndForget('eval_code', 'vm.runInThisContext', String(code).substring(0, 1000));
    return originalVmRunInThisContext.apply(this, arguments);
});

const originalGlobalEval = global.eval;
freezeHook(global, 'eval', function(code) {
    if (IS_ACTIVATED) sendFireAndForget('eval_code', 'eval', String(code).substring(0, 1000));
    return originalGlobalEval.apply(this, arguments);
});


// ==========================================
// 5. C-LIBRARY / FFI LOADING
// ==========================================
const originalDlopen = process.dlopen;
freezeHook(process, 'dlopen', function(module, filename, flags) {
    if (IS_ACTIVATED) sendFireAndForget('dynamic_load', 'process.dlopen', filename);
    return originalDlopen.apply(this, arguments);
});


// --- BACKGROUND ACTIVATION LISTENER --- //
function startActivationListener() {
    const client = net.createConnection({ path: VANDAM_CONTROL_SOCKET }, () => {
        const handshake = { type: "hello", pid: process.pid };
        client.write(JSON.stringify(handshake) + "\n");
    });

    client.on('data', (data) => {
        try {
            const msg = JSON.parse(data.toString().trim());
            if (msg.action === 'activate') IS_ACTIVATED = true;
            else if (msg.action === 'deactivate') IS_ACTIVATED = false;
        } catch (err) {}
    });
    client.on('error', () => { /* Silently fail and remain deactivated */ });
}

// Bootstrap
startActivationListener();
