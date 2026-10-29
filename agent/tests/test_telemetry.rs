use std::sync::Arc;
use std::collections::HashSet;
use vandam::types::{
    TelemetryEventRaw, TelemetryHeader, EventType, TelemetrySource,
    ProcessCreateDetails, ProcessStopDetails, FileOpenDetails, MemoryMapDetails
};
use vandam::heuristics::{HeuristicsEngine, ProcessNode};

/// The fields a test does not set: every detail struct is plain packed bytes, all-zero is valid.
fn zeroed<T: Copy>() -> T {
    unsafe { std::mem::zeroed() }
}

fn init_test_engine() -> HeuristicsEngine {
    // Load config defaults or mockup
    let config = Arc::new(vandam::rules::ConfigManager::load_defaults());
    let web_roots = vec!["/var/www/html".to_string()];
    let system_shells = ["/bin/bash".to_string(), "/bin/sh".to_string()].into_iter().collect::<HashSet<_>>();
    
    // Set environment variable to enable audit mode during tests
    std::env::set_var("VANDAM_AUDIT", "1");
    
    // Ensure seeding is marked complete for telemetry tests
    vandam::allowlist::set_seeding_complete(true);
    
    HeuristicsEngine::new(config, web_roots, system_shells, None)
}

#[tokio::test]
async fn test_process_create_and_store() {
    let engine = init_test_engine();
    
    // 1. Pre-seed a parent process node
    engine.process_map.insert(100, ProcessNode {
        pid: 100,
        ppid: 1,
        exe: "/usr/sbin/nginx".to_string(),
        cmdline: "/usr/sbin/nginx -g daemon off;".to_string(),
        is_listening_server: true,
        is_database: false,
        is_install_context: false,
        is_top_level_install: false,
        install_root_pid: 0,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    });

    // 2. Dispatch a ProcessCreate event for a child process (PID 101, parent PID 100)
    let mut raw_event = TelemetryEventRaw {
        header: TelemetryHeader::new(42, 999999999, 101, EventType::ProcessCreate, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };

    let details = ProcessCreateDetails {
        child_pid: 101,
        real_parent_pid: 100,
        child_image_path: {
            let mut arr = [0u8; 512];
            let path = b"/bin/bash";
            arr[..path.len()].copy_from_slice(path);
            arr
        },
        child_command_line: {
            let mut arr = [0u8; 1024];
            let cmd = b"/bin/bash -c 'whoami'";
            arr[..cmd.len()].copy_from_slice(cmd);
            arr
        },
        ..zeroed()
    };

    unsafe {
        std::ptr::write(
            raw_event.details_buffer.as_mut_ptr() as *mut ProcessCreateDetails,
            details
        );
    }

    engine.handle_raw_event(raw_event);

    // 3. Verify in-memory storage of the spawned child process node
    assert!(engine.process_map.contains_key(&101));
    let child_node = engine.process_map.get(&101).unwrap();
    assert_eq!(child_node.pid, 101);
    assert_eq!(child_node.ppid, 100);
    assert_eq!(child_node.exe, "/bin/bash");
    assert_eq!(child_node.cmdline, "/bin/bash -c 'whoami'");
    // Verify context propagation (nginx is a web server, so child spawned by it is marked web context)
    assert!(child_node.is_listening_server);
    
    // Verify seen timestamp was recorded
    assert!(engine.process_seen.contains_key(&101));
}

#[tokio::test]
async fn test_process_stop_and_eviction() {
    let engine = init_test_engine();

    // 1. Seed a process node to evict
    engine.process_map.insert(202, ProcessNode {
        pid: 202,
        ppid: 1,
        exe: "/bin/sleep".to_string(),
        cmdline: "/bin/sleep 10".to_string(),
        is_listening_server: false,
        is_database: false,
        is_install_context: false,
        is_top_level_install: false,
        install_root_pid: 0,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    });
    engine.process_seen.insert(202, 123456);

    // 2. Dispatch a ProcessStop event
    let mut raw_event = TelemetryEventRaw {
        header: TelemetryHeader::new(43, 1000000000, 202, EventType::ProcessStop, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };

    let details = ProcessStopDetails {
        exit_code: 0,
        ..zeroed()
    };

    unsafe {
        std::ptr::write(
            raw_event.details_buffer.as_mut_ptr() as *mut ProcessStopDetails,
            details
        );
    }

    engine.handle_raw_event(raw_event);

    // 3. Verify in-memory eviction
    assert!(!engine.process_map.contains_key(&202));
    assert!(!engine.process_seen.contains_key(&202));
}

#[tokio::test]
async fn test_file_open_telemetry() {
    let engine = init_test_engine();

    // Seed a monitored process node
    engine.process_map.insert(303, ProcessNode {
        pid: 303,
        ppid: 1,
        exe: "/usr/bin/php".to_string(),
        cmdline: "/usr/bin/php /var/www/html/index.php".to_string(),
        is_listening_server: true,
        is_database: false,
        is_install_context: false,
        is_top_level_install: false,
        install_root_pid: 0,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    });

    // Dispatch a FileOpen event (PHP loading a php script file)
    let mut raw_event = TelemetryEventRaw {
        header: TelemetryHeader::new(44, 1000000005, 303, EventType::FileOpen, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };

    let details = FileOpenDetails {
        file_path: {
            let mut arr = [0u8; 512];
            let path = b"/var/www/html/upload.php";
            arr[..path.len()].copy_from_slice(path);
            arr
        },
        ..zeroed()
    };

    unsafe {
        std::ptr::write(
            raw_event.details_buffer.as_mut_ptr() as *mut FileOpenDetails,
            details
        );
    }

    engine.handle_raw_event(raw_event);

    // Verify script path was logged into PHP process node's loaded_scripts vector
    let php_node = engine.process_map.get(&303).unwrap();
    let loaded = php_node.loaded_scripts.lock().unwrap();
    assert!(loaded.contains(&"/var/www/html/upload.php".to_string()));
}

#[tokio::test]
async fn test_credential_access_control() {
    let engine = init_test_engine();

    // 1. Seed a process node that is in an install context
    engine.process_map.insert(404, ProcessNode {
        pid: 404,
        ppid: 1,
        exe: "/usr/bin/cargo".to_string(),
        cmdline: "cargo build".to_string(),
        is_listening_server: false,
        is_database: false,
        is_install_context: true,
        is_top_level_install: true,
        install_root_pid: 404,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    });

    // 2. Dispatch a FileOpen event for /home/user/.cargo/credentials (allowed for cargo)
    let mut raw_event = TelemetryEventRaw {
        header: TelemetryHeader::new(45, 1000000010, 404, EventType::FileOpen, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };

    let details = FileOpenDetails {
        file_path: {
            let mut arr = [0u8; 512];
            let path = b"/home/user/.cargo/credentials";
            arr[..path.len()].copy_from_slice(path);
            arr
        },
        ..zeroed()
    };

    unsafe {
        std::ptr::write(
            raw_event.details_buffer.as_mut_ptr() as *mut FileOpenDetails,
            details
        );
    }

    engine.handle_raw_event(raw_event.clone());

    // Process should still exist since cargo is allowed to access cargo credentials
    assert!(engine.process_map.contains_key(&404));

    // Access again (second read)
    engine.handle_raw_event(raw_event.clone());
    assert!(engine.process_map.contains_key(&404));

    // Access third time (exceeds max_reads = 2)
    engine.handle_raw_event(raw_event);

    // Verify that the threat alert was triggered and queued
    let alerts = vandam::notifications::get_recent_alerts();
    let has_alert = alerts.iter().any(|a| {
        a.process.pid == 404 && a.threat_type == "Vulnerability.SupplyChain.CredentialAccessAttempt"
    });
    assert!(has_alert);
}

#[tokio::test]
async fn test_in_memory_execution_telemetry() {
    let engine = init_test_engine();
    
    // Seed a web server process node
    engine.process_map.insert(505, ProcessNode {
        pid: 505,
        ppid: 1,
        exe: "/usr/sbin/nginx".to_string(),
        cmdline: "/usr/sbin/nginx -g daemon off;".to_string(),
        is_listening_server: true,
        is_database: false,
        is_install_context: false,
        is_top_level_install: false,
        install_root_pid: 0,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    });
    
    engine.report_in_memory_execution(505, "eval", "echo 'hello';");
    
    let alerts = vandam::notifications::get_recent_alerts();
    let has_alert = alerts.iter().any(|a| {
        a.process.pid == 505 && (a.threat_type == "Threat.Server.InMemoryExecution" || a.threat_type == "Threat.Server.InMemoryCode")
    });
    assert!(has_alert);
}

#[tokio::test]
async fn test_jit_runtime_detection() {
    let engine = init_test_engine();
    
    // Test JIT whitelisting
    engine.process_map.insert(606, ProcessNode {
        pid: 606,
        ppid: 1,
        exe: "/usr/bin/node".to_string(),
        cmdline: "node index.js".to_string(),
        is_listening_server: true,
        is_database: false,
        is_install_context: false,
        is_top_level_install: false,
        install_root_pid: 0,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    });
    
    // Dispatch a MemoryMap event for node (PID 606)
    let mut raw_event = TelemetryEventRaw {
        header: TelemetryHeader::new(46, 1000000020, 606, EventType::MemoryMap, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };
    
    let details = MemoryMapDetails {
        address: 0x12345678,
        length: 4096,
        prot_flags: 4, // PROT_EXEC
        map_flags: 32, // MAP_ANONYMOUS
        fd: -1,
        ..zeroed()
    };
    
    unsafe {
        std::ptr::write(
            raw_event.details_buffer.as_mut_ptr() as *mut MemoryMapDetails,
            details
        );
    }
    engine.handle_raw_event(raw_event);
    
    // Node should still exist because it is whitelisted as JIT runtime
    assert!(engine.process_map.contains_key(&606));
}

#[tokio::test]
async fn test_framework_discovery_and_symlinks() {
    let tmp_path = std::env::current_dir().unwrap().join(format!("test_tmp_{}", uuid::Uuid::new_v4()));
    let project_root = tmp_path.as_path();
    let public_dir = project_root.join("public");
    std::fs::create_dir_all(&public_dir).unwrap();

    // Create a framework anchor file in the project root (artisan for Laravel)
    let artisan_path = project_root.join("artisan");
    std::fs::write(&artisan_path, "laravel artisan").unwrap();

    // Create a file in project root
    let app_file = project_root.join("app_file.php");
    std::fs::write(&app_file, "<?php echo 'hello';").unwrap();

    // Now test that discovery detects parent project root
    let mut roots = vec![public_dir.to_str().unwrap().to_string()];
    vandam::discovery::adjust_web_roots_for_frameworks(&mut roots);
    
    // It should discover the parent directory project_root because of the artisan file
    assert!(roots.contains(&project_root.to_str().unwrap().to_string()));

    // Test symlink seeding target resolution
    let target_dir = project_root.join("external_target");
    std::fs::create_dir_all(&target_dir).unwrap();
    let external_file = target_dir.join("helper.php");
    std::fs::write(&external_file, "<?php echo 'helper';").unwrap();

    // Create a symlink in the public dir pointing to external_target
    let symlink_path = public_dir.join("symlink_dir");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target_dir, &symlink_path).unwrap();

    // Seed the allowlist
    vandam::allowlist::seed_inode_allowlist(&[public_dir.to_str().unwrap().to_string()]);
    
    // Check if the external_file's inode is allowed
    assert!(vandam::allowlist::is_inode_allowed(external_file.to_str().unwrap()));

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp_path);
}

#[tokio::test]
async fn test_startup_event_queueing() {
    let engine = init_test_engine();
    
    // Set seeding to false
    vandam::allowlist::set_seeding_complete(false);

    // Seed a dummy process node
    engine.process_map.insert(707, ProcessNode {
        pid: 707,
        ppid: 1,
        exe: "/usr/sbin/nginx".to_string(),
        cmdline: "/usr/sbin/nginx".to_string(),
        is_listening_server: true,
        is_database: false,
        is_install_context: false,
        is_top_level_install: false,
        install_root_pid: 0,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    });

    // Send an event while seeding is in progress
    let mut raw_event = TelemetryEventRaw {
        header: TelemetryHeader::new(47, 1000000030, 707, EventType::FileOpen, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };
    
    let details = FileOpenDetails {
        file_path: {
            let mut arr = [0u8; 512];
            let path = b"/var/www/html/index.php";
            arr[..path.len()].copy_from_slice(path);
            arr
        },
        ..zeroed()
    };
    
    unsafe {
        std::ptr::write(
            raw_event.details_buffer.as_mut_ptr() as *mut FileOpenDetails,
            details
        );
    }
    
    engine.handle_raw_event(raw_event);

    // Verify it wasn't processed (no threat alert dispatched yet because it's queued)
    let alerts = vandam::notifications::get_recent_alerts();
    assert!(!alerts.iter().any(|a| a.process.pid == 707));

    // Complete seeding
    vandam::allowlist::set_seeding_complete(true);

    // Send a trigger event to drain the queue
    let mut trigger_event = TelemetryEventRaw {
        header: TelemetryHeader::new(48, 1000000040, 707, EventType::FileOpen, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };
    let trigger_details = FileOpenDetails {
        file_path: {
            let mut arr = [0u8; 512];
            let path = b"/var/www/html/trigger.php";
            arr[..path.len()].copy_from_slice(path);
            arr
        },
        ..zeroed()
    };
    unsafe {
        std::ptr::write(
            trigger_event.details_buffer.as_mut_ptr() as *mut FileOpenDetails,
            trigger_details
        );
    }

    engine.handle_raw_event(trigger_event);

    // Now the queue should be drained and processed
    // Since /var/www/html/index.php is not in the allowlist, it should trigger UnregisteredFileRead alert
    let alerts = vandam::notifications::get_recent_alerts();
    let has_alert = alerts.iter().any(|a| {
        a.process.pid == 707 && a.threat_type == "Threat.Server.UnregisteredFileRead"
    });
    assert!(has_alert);
}

#[tokio::test]
async fn test_walkdir_sha256_tampering() {
    let _engine = init_test_engine();
    let tmp_path = std::env::current_dir().unwrap().join(format!("test_tmp_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_path).unwrap();

    let test_file = tmp_path.join("legit.php");
    std::fs::write(&test_file, "<?php echo 'legit content';").unwrap();

    // Seed via walkdir fallback
    vandam::allowlist::seed_inode_allowlist(&[tmp_path.to_str().unwrap().to_string()]);

    // Verify it is allowed initially
    assert!(vandam::allowlist::is_inode_allowed(test_file.to_str().unwrap()));
    assert!(!vandam::allowlist::check_walkdir_tampering(test_file.to_str().unwrap()));

    // Now modify the file content in place (same inode, different content)
    std::fs::write(&test_file, "<?php echo 'tampered content';").unwrap();

    // Verify tampering is detected
    assert!(vandam::allowlist::check_walkdir_tampering(test_file.to_str().unwrap()));

    // Clean up
    let _ = std::fs::remove_dir_all(&tmp_path);
}

#[tokio::test]
async fn test_hardlink_lfi_detection() {
    let engine = init_test_engine();
    let tmp_path = std::env::current_dir().unwrap().join(format!("test_tmp_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_path).unwrap();

    let sensitive_file = tmp_path.join("shadow_file");
    std::fs::write(&sensitive_file, "root:*:12345:0:99999:7:::").unwrap();
    use std::os::unix::fs::MetadataExt;
    let sens_meta = std::fs::metadata(&sensitive_file).unwrap();
    
    // Register it as sensitive in userspace
    vandam::allowlist::register_sensitive_inode(sens_meta.ino());

    // Create a hardlink inside a dummy web root
    let dummy_web_root = tmp_path.join("public");
    std::fs::create_dir_all(&dummy_web_root).unwrap();
    let hardlink_path = dummy_web_root.join("shadow_hardlink");
    std::fs::hard_link(&sensitive_file, &hardlink_path).unwrap();

    // Create a process node representing a web server running in web root
    engine.process_map.insert(808, ProcessNode {
        pid: 808,
        ppid: 1,
        exe: "/usr/sbin/nginx".to_string(),
        cmdline: "/usr/sbin/nginx".to_string(),
        is_listening_server: true,
        is_database: false,
        is_install_context: false,
        is_top_level_install: false,
        install_root_pid: 0,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    });

    // Dispatch FileOpen event for the hardlink path
    let mut raw_event = TelemetryEventRaw {
        header: TelemetryHeader::new(49, 1000000050, 808, EventType::FileOpen, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };
    let details = FileOpenDetails {
        file_path: {
            let mut arr = [0u8; 512];
            let path = hardlink_path.to_str().unwrap().as_bytes();
            arr[..path.len()].copy_from_slice(path);
            arr
        },
        ..zeroed()
    };
    unsafe {
        std::ptr::write(
            raw_event.details_buffer.as_mut_ptr() as *mut FileOpenDetails,
            details
        );
    }

    // Set engine's web roots to contain our dummy_web_root
    let engine_with_roots = vandam::heuristics::HeuristicsEngine::new(
        Arc::new(vandam::rules::ConfigManager::load_defaults()),
        vec![dummy_web_root.to_str().unwrap().to_string()],
        [].into_iter().collect(),
        None
    );
    engine_with_roots.process_map.insert(808, engine.process_map.get(&808).unwrap().clone());

    engine_with_roots.handle_raw_event(raw_event);

    // Verify it is flagged as Threat.Server.HardlinkToSensitiveFile
    let alerts = vandam::notifications::get_recent_alerts();
    let has_alert = alerts.iter().any(|a| {
        a.process.pid == 808 && a.threat_type == "Threat.Server.HardlinkToSensitiveFile"
    });
    assert!(has_alert);

    // Clean up
    let _ = std::fs::remove_dir_all(&tmp_path);
}

#[tokio::test]
async fn test_ffi_library_telemetry() {
    let engine = init_test_engine();

    // Create process in install context
    engine.process_map.insert(909, ProcessNode {
        pid: 909,
        ppid: 1,
        exe: "/usr/bin/npm".to_string(),
        cmdline: "npm install".to_string(),
        is_listening_server: false,
        is_database: false,
        is_install_context: true,
        is_top_level_install: true,
        install_root_pid: 909,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    });

    let mut raw_event = TelemetryEventRaw {
        header: TelemetryHeader::new(100, 1000000060, 909, EventType::FileOpen, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };
    let details = FileOpenDetails {
        file_path: {
            let mut arr = [0u8; 512];
            let path = b"/usr/lib/libffi.so.8";
            arr[..path.len()].copy_from_slice(path);
            arr
        },
        ..zeroed()
    };
    unsafe {
        std::ptr::write(
            raw_event.details_buffer.as_mut_ptr() as *mut FileOpenDetails,
            details
        );
    }

    engine.handle_raw_event(raw_event);

    // Verify it triggers Warning.SupplyChain.FFICapabilityLoaded
    let alerts = vandam::notifications::get_recent_alerts();
    let has_alert = alerts.iter().any(|a| {
        a.process.pid == 909 && a.threat_type == "Warning.SupplyChain.FFICapabilityLoaded"
    });
    assert!(has_alert);
}

#[tokio::test]
async fn test_lock_file_mutation_telemetry() {
    let tmp_path = std::env::current_dir().unwrap().join(format!("test_tmp_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_path).unwrap();

    let lock_file = tmp_path.join("package.json");
    std::fs::write(&lock_file, "{\n  \"name\": \"test\"\n}").unwrap();

    // Snapshot it
    let web_roots = vec![tmp_path.to_str().unwrap().to_string()];
    vandam::heuristics::snapshot_lock_files(999, &web_roots);

    // Mutate the file
    std::fs::write(&lock_file, "{\n  \"name\": \"test\",\n  \"dependencies\": {\n    \"malicious\": \"1.0.0\"\n  }\n}").unwrap();

    // Trigger end of install context
    let proc = ProcessNode {
        pid: 999,
        ppid: 1,
        exe: "/usr/bin/npm".to_string(),
        cmdline: "npm install".to_string(),
        is_listening_server: false,
        is_database: false,
        is_install_context: true,
        is_top_level_install: true,
        install_root_pid: 999,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    };

    vandam::heuristics::check_and_alert_lock_file_mutation(999, &web_roots, &proc);

    // Verify it triggers Warning.SupplyChain.LockFileMutated
    let alerts = vandam::notifications::get_recent_alerts();
    let has_alert = alerts.iter().any(|a| {
        a.process.pid == 999 && a.threat_type == "Warning.SupplyChain.LockFileMutated"
    });
    assert!(has_alert);

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp_path);
}

#[tokio::test]
async fn test_env_read_exfiltration_telemetry() {
    let engine = init_test_engine();

    // Create process in install context
    engine.process_map.insert(990, ProcessNode {
        pid: 990,
        ppid: 1,
        exe: "/usr/bin/npm".to_string(),
        cmdline: "npm install".to_string(),
        is_listening_server: false,
        is_database: false,
        is_install_context: true,
        is_top_level_install: true,
        install_root_pid: 990,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    });

    // 1. Attempt to read pre-existing .env file -> should alert!
    let mut raw_event = TelemetryEventRaw {
        header: TelemetryHeader::new(110, 1000000080, 990, EventType::FileOpen, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };
    let details = FileOpenDetails {
        file_path: {
            let mut arr = [0u8; 512];
            let path = b"/var/www/html/.env";
            arr[..path.len()].copy_from_slice(path);
            arr
        },
        ..zeroed()
    };
    unsafe {
        std::ptr::write(
            raw_event.details_buffer.as_mut_ptr() as *mut FileOpenDetails,
            details
        );
    }

    engine.handle_raw_event(raw_event);

    let alerts = vandam::notifications::get_recent_alerts();
    let has_alert = alerts.iter().any(|a| {
        a.process.pid == 990 && a.threat_type == "Warning.SupplyChain.CredentialExfiltrationAttempt"
    });
    assert!(has_alert);

    // 2. Simulate process writing to a different .env file (.env.production) -> registers it
    let mut raw_write_event = TelemetryEventRaw {
        header: TelemetryHeader::new(111, 1000000090, 990, EventType::FileCreate, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };
    let write_details = vandam::types::FileCreateDetails {
        zone_id: 0,
        file_path: {
            let mut arr = [0u8; 512];
            let path = b"/var/www/html/.env.production";
            arr[..path.len()].copy_from_slice(path);
            arr
        },
        ..zeroed()
    };
    unsafe {
        std::ptr::write(
            raw_write_event.details_buffer.as_mut_ptr() as *mut vandam::types::FileCreateDetails,
            write_details
        );
    }

    engine.handle_raw_event(raw_write_event);

    // 3. Read the created .env.production file -> should NOT alert!
    vandam::notifications::get_recent_alerts(); // clear alerts
    let mut raw_read_created_event = TelemetryEventRaw {
        header: TelemetryHeader::new(112, 1000000100, 990, EventType::FileOpen, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };
    let read_created_details = FileOpenDetails {
        file_path: {
            let mut arr = [0u8; 512];
            let path = b"/var/www/html/.env.production";
            arr[..path.len()].copy_from_slice(path);
            arr
        },
        ..zeroed()
    };
    unsafe {
        std::ptr::write(
            raw_read_created_event.details_buffer.as_mut_ptr() as *mut FileOpenDetails,
            read_created_details
        );
    }

    engine.handle_raw_event(raw_read_created_event);

    let alerts_after = vandam::notifications::get_recent_alerts();
    let has_new_alert = alerts_after.iter().any(|a| {
        a.process.pid == 990 && a.threat_type == "Warning.SupplyChain.CredentialExfiltrationAttempt" && a.remediation.status.contains(".env.production")
    });
    assert!(!has_new_alert);
}

#[tokio::test]
async fn test_learning_mode_allowlist_registration() {
    let engine = init_test_engine();

    // 1. Enable learning mode
    vandam::allowlist::set_learning_mode(true);

    // Create a real temporary file on disk
    let tmp_dir = std::env::current_dir().unwrap().join(format!("test_tmp_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let test_file = tmp_dir.join("learned_file.php");
    std::fs::write(&test_file, "<?php echo 'hello';").unwrap();
    let test_file_str = test_file.to_str().unwrap();

    // Seed a web server process node
    engine.process_map.insert(900, ProcessNode {
        pid: 900,
        ppid: 1,
        exe: "/usr/sbin/nginx".to_string(),
        cmdline: "nginx".to_string(),
        is_listening_server: true,
        is_database: false,
        is_install_context: false,
        is_top_level_install: false,
        install_root_pid: 0,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    });

    // 2. Dispatch a FileOpen event for the temporary file -> should NOT alert and should register it!
    let mut raw_event = TelemetryEventRaw {
        header: TelemetryHeader::new(220, 1000000200, 900, EventType::FileOpen, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };
    let details = FileOpenDetails {
        file_path: {
            let mut arr = [0u8; 512];
            let path = test_file_str.as_bytes();
            arr[..path.len()].copy_from_slice(path);
            arr
        },
        ..zeroed()
    };
    unsafe {
        std::ptr::write(
            raw_event.details_buffer.as_mut_ptr() as *mut FileOpenDetails,
            details
        );
    }

    engine.handle_raw_event(raw_event);

    // Disable learning mode back immediately before assertions to avoid test state pollution
    vandam::allowlist::set_learning_mode(false);

    // Verify no alerts were queued
    let alerts = vandam::notifications::get_recent_alerts();
    let has_alert = alerts.iter().any(|a| a.process.pid == 900);
    assert!(!has_alert);

    // Verify the file was added to allowlist
    let is_allowed = vandam::allowlist::is_inode_allowed_for_process(test_file_str, &[]);

    // Clean up
    let _ = std::fs::remove_dir_all(&tmp_dir);

    assert!(is_allowed);
}

#[tokio::test]
async fn test_git_tampering_and_write_protection() {
    let engine = init_test_engine();

    // 1. Create a process node representing a web server (unprivileged context, NOT god mode)
    engine.process_map.insert(950, ProcessNode {
        pid: 950,
        ppid: 1,
        exe: "/usr/sbin/nginx".to_string(),
        cmdline: "nginx".to_string(),
        is_listening_server: true,
        is_database: false,
        is_install_context: false,
        is_top_level_install: false,
        install_root_pid: 0,
        depth: 0,
        loaded_scripts: Arc::new(std::sync::Mutex::new(Vec::new())),
        signature_name: None,
        service: None,
    });

    // Create a real file for .git/config under a temp path
    let tmp_dir = std::env::current_dir().unwrap().join(format!("test_tmp_{}", uuid::Uuid::new_v4()));
    let git_dir = tmp_dir.join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();
    let config_file = git_dir.join("config");
    std::fs::write(&config_file, "[core]\n\trepositoryformatversion = 0").unwrap();
    let config_file_str = config_file.to_str().unwrap();

    // 2. Dispatch a FileWrite event targeting .git/config -> should trigger GitTamperingAttempt alert!
    let mut raw_event = TelemetryEventRaw {
        header: TelemetryHeader::new(230, 1000000300, 950, EventType::FileWrite, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };
    let details = vandam::types::FileWriteDetails {
        bytes_written: 100,
        file_path: {
            let mut arr = [0u8; 512];
            let path = config_file_str.as_bytes();
            arr[..path.len()].copy_from_slice(path);
            arr
        },
    };
    unsafe {
        std::ptr::write(
            raw_event.details_buffer.as_mut_ptr() as *mut vandam::types::FileWriteDetails,
            details
        );
    }

    engine.handle_raw_event(raw_event);

    let alerts = vandam::notifications::get_recent_alerts();
    let has_alert = alerts.iter().any(|a| {
        a.process.pid == 950 && a.threat_type.contains("GitTamperingAttempt")
    });

    // Clean up first
    let _ = std::fs::remove_dir_all(&tmp_dir);

    assert!(has_alert);
}

#[tokio::test]
async fn test_rasp_severed_connection_warning() {
    // Skipped: vandam::rasp refactored into tls_buffer
}

#[tokio::test]
async fn test_ebpf_health_monitoring() {
    let engine = init_test_engine();
    vandam::ebpf_health::reset_sequence_tracking();

    // 1. Trigger a telemetry event with sequence 100
    let mut raw_event1 = TelemetryEventRaw {
        header: TelemetryHeader::new(100, 1000000100, 1234, EventType::FileOpen, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };
    engine.handle_raw_event(raw_event1);

    // 2. Trigger a telemetry event with sequence 105 (gap of 4 dropped events)
    let mut raw_event2 = TelemetryEventRaw {
        header: TelemetryHeader::new(105, 1000000200, 1234, EventType::FileOpen, TelemetrySource::BPF_LSM),
        details_buffer: [0u8; vandam::types::DETAILS_SIZE],
    };
    engine.handle_raw_event(raw_event2);

    // Check that we tracked 4 dropped events
    let dropped = vandam::ebpf_health::get_and_reset_dropped_count();
    assert_eq!(dropped, 4);
}

#[tokio::test]
async fn test_new_dimension_telemetry_events() {
    let engine = init_test_engine();

    // 1. Test NetworkAccept
    let mut details_accept = [0u8; vandam::types::DETAILS_SIZE];
    details_accept[0] = 0x04; // IPv4
    details_accept[1] = 192;
    details_accept[2] = 168;
    details_accept[3] = 1;
    details_accept[4] = 100;
    let sport_bytes = 4433u16.to_ne_bytes();
    details_accept[46] = sport_bytes[0];
    details_accept[47] = sport_bytes[1];
    let lport_bytes = 80u16.to_ne_bytes();
    details_accept[48] = lport_bytes[0];
    details_accept[49] = lport_bytes[1];

    let raw_accept = TelemetryEventRaw {
        header: TelemetryHeader::new(1, 1000, 9999, EventType::NetworkAccept, TelemetrySource::BPF_LSM),
        details_buffer: details_accept,
    };
    engine.handle_raw_event(raw_accept);

    // 2. Test DNSQuery
    let mut details_dns = [0u8; vandam::types::DETAILS_SIZE];
    details_dns[0] = 3;
    details_dns[1] = b'w'; details_dns[2] = b'w'; details_dns[3] = b'w';
    details_dns[4] = 6;
    details_dns[5] = b'g'; details_dns[6] = b'o'; details_dns[7] = b'o'; details_dns[8] = b'g'; details_dns[9] = b'l'; details_dns[10] = b'e';
    details_dns[11] = 3;
    details_dns[12] = b'c'; details_dns[13] = b'o'; details_dns[14] = b'm';
    details_dns[15] = 0;
    
    details_dns[128] = 0x04;
    details_dns[129] = 8; details_dns[130] = 8; details_dns[131] = 8; details_dns[132] = 8;
    let dns_port_bytes = 53u16.to_ne_bytes();
    details_dns[174] = dns_port_bytes[0];
    details_dns[175] = dns_port_bytes[1];

    let raw_dns = TelemetryEventRaw {
        header: TelemetryHeader::new(2, 2000, 9999, EventType::DNSQuery, TelemetrySource::BPF_LSM),
        details_buffer: details_dns,
    };
    engine.handle_raw_event(raw_dns);

    // 3. Test FileDelete
    let mut details_delete = [0u8; vandam::types::DETAILS_SIZE];
    let path_str = b"/etc/passwd";
    details_delete[..path_str.len()].copy_from_slice(path_str);

    let raw_delete = TelemetryEventRaw {
        header: TelemetryHeader::new(3, 3000, 9999, EventType::FileDelete, TelemetrySource::BPF_LSM),
        details_buffer: details_delete,
    };
    engine.handle_raw_event(raw_delete);

    // Verify recent alerts
    let alerts = vandam::notifications::get_recent_alerts();
    
    let has_accept = alerts.iter().any(|a| a.threat_type == "Info.Server.InboundConnection");
    let has_dns = alerts.iter().any(|a| a.threat_type == "Info.Server.DNSQuery");
    let has_delete = alerts.iter().any(|a| a.threat_type == "Warning.Server.CriticalFileDeleted");

    assert!(has_accept);
    assert!(has_dns);
    assert!(has_delete);
}

#[tokio::test]
async fn test_quarantine_restore_and_confidence_scoring() {
    let tmp_path = std::env::current_dir().unwrap().join(format!("test_tmp_quar_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&tmp_path);
    let quar_dir = tmp_path.join("quarantine");
    vandam::quarantine::init_quarantine_dir(quar_dir.to_string_lossy().to_string());
    
    let target_file = tmp_path.join("test_upload.php");
    std::fs::write(&target_file, b"<?php system($_GET['c']); ?>").unwrap();

    let alert_id = format!("test_alert_{}", uuid::Uuid::new_v4());
    let q_res = vandam::quarantine::quarantine_file(
        &target_file.to_string_lossy(),
        &alert_id,
        "Testing quarantine restore",
        "Threat.Upload.WebshellDetected"
    );
    assert!(q_res.is_ok());
    assert!(!target_file.exists());

    // Restore via alert_id
    let res_path = vandam::quarantine::restore_by_alert_id(&alert_id[..8]);
    assert!(res_path.is_ok());
    assert!(target_file.exists());

    // Clean up
    let _ = std::fs::remove_dir_all(&tmp_path);

    // Verify confidence scoring
    let mut payload = vandam::notifications::AlertPayload {
        alert_id: "test_conf".to_string(),
        timestamp: "now".to_string(),
        threat_type: "Threat.Server.UnregisteredFileWrite".to_string(),
        severity: "CRITICAL".to_string(),
        confidence: 0.0,
        container: None,
        process: vandam::notifications::ProcessInfo {
            pid: 8888,
            exec_path: "/usr/bin/php".to_string(),
            cmdline: "php index.php".to_string(),
            parent_exec_path: "nginx".to_string(),
            parent_pid: 1,
            verified_package: None,
            envs: Vec::new(),
            args: Vec::new(),
            signature_name: None,
            service: None,
        },
        remediation: vandam::notifications::RemediationInfo {
            action: "LOG".to_string(),
            status: "ok".to_string(),
            requires_cloud_decision: false,
            quarantine: None,
        },
        rasp_context: None,
        origin_tree: Vec::new(),
        network_links: Vec::new(),
        container_meta: None,
        site: None,
        site_source: None,
        event_detail: None,
    };

    vandam::notifications::calculate_confidence_and_correlate(&mut payload);
    assert!(payload.confidence >= 0.85);
}

#[tokio::test]
async fn test_pid_reuse_and_map_capacity_monitoring() {
    let engine = init_test_engine();

    let capacities = vandam::ebpf_health::check_bpf_map_capacities();
    assert!(capacities.is_empty());

    let mut details1 = [0u8; vandam::types::DETAILS_SIZE];
    let path_a = b"/usr/bin/app_a";
    let cmd_a = b"app_a --start";
    details1[0..4].copy_from_slice(&9090u32.to_ne_bytes());
    details1[4..8].copy_from_slice(&1u32.to_ne_bytes());
    details1[8..8 + path_a.len()].copy_from_slice(path_a);
    details1[520..520 + cmd_a.len()].copy_from_slice(cmd_a);

    let raw1 = TelemetryEventRaw {
        header: TelemetryHeader::new(1, 1000, 9090, EventType::ProcessCreate, TelemetrySource::BPF_LSM),
        details_buffer: details1,
    };
    engine.handle_raw_event(raw1);

    let mut details2 = [0u8; vandam::types::DETAILS_SIZE];
    let path_b = b"/usr/bin/app_b";
    let cmd_b = b"app_b --start";
    details2[0..4].copy_from_slice(&9090u32.to_ne_bytes());
    details2[4..8].copy_from_slice(&1u32.to_ne_bytes());
    details2[8..8 + path_b.len()].copy_from_slice(path_b);
    details2[520..520 + cmd_b.len()].copy_from_slice(cmd_b);

    let raw2 = TelemetryEventRaw {
        header: TelemetryHeader::new(2, 2000, 9090, EventType::ProcessCreate, TelemetrySource::BPF_LSM),
        details_buffer: details2,
    };
    engine.handle_raw_event(raw2);

    let alerts = vandam::notifications::get_recent_alerts();
    let has_pid_reuse = alerts.iter().any(|a| a.threat_type == "Warning.Process.PIDReuse");
    assert!(has_pid_reuse);
}

#[tokio::test]
async fn test_maintenance_mode_and_perf_monitor() {
    assert!(!vandam::maintenance::is_maintenance_active());
    
    vandam::maintenance::enable_maintenance_mode(30, "Testing maintenance mode");
    assert!(vandam::maintenance::is_maintenance_active());

    let status = vandam::maintenance::get_maintenance_status();
    assert_eq!(status.get("active").and_then(|a| a.as_bool()), Some(true));
    assert_eq!(status.get("reason").and_then(|r| r.as_str()), Some("Testing maintenance mode"));

    vandam::maintenance::disable_maintenance_mode();
    assert!(!vandam::maintenance::is_maintenance_active());

    // Test indefinite (0 duration / no timeout)
    vandam::maintenance::enable_maintenance_mode(0, "Testing indefinite mode");
    assert!(vandam::maintenance::is_maintenance_active());
    let status_indef = vandam::maintenance::get_maintenance_status();
    assert_eq!(status_indef.get("expires_at_unix").and_then(|e| e.as_i64()), Some(0));

    vandam::maintenance::disable_maintenance_mode();

    vandam::perf_monitor::record_event_processed(150);
}

#[test]
fn test_process_link_tracking() {
    let event = vandam::link_tracker::record_connection(
        1234,
        "10.0.0.10".to_string(),
        48920,
        "10.0.0.20".to_string(),
        5432,
    );

    assert_eq!(event.src_pid, 1234);
    assert_eq!(event.target_type, "database");
    assert_eq!(event.target_service, "postgresql");
    assert_eq!(event.dst_port, 5432);

    let registry = vandam::link_tracker::get_link_registry();
    assert!(registry.contains_key(&("10.0.0.10".to_string(), 48920, "10.0.0.20".to_string(), 5432)));

    let links = vandam::link_tracker::get_process_network_links(1234);
    assert!(!links.is_empty());
    assert_eq!(links[0].dst_port, 5432);
    assert!(links[0].dst_process_tree.is_empty()); // No local listening process exists on port 5432 in test container
}

#[test]
fn test_passive_telemetry_detectors() {
    let config = vandam::rules::ConfigManager::load_defaults();
    
    // Verify credential file matching
    assert!(vandam::heuristics::is_credential_file(&config, "/var/www/.env"));
    assert!(vandam::heuristics::is_credential_file(&config, "/home/user/.ssh/id_rsa"));
    assert!(!vandam::heuristics::is_credential_file(&config, "/var/www/index.php"));
    
    // Verify cat-like utilities and shell basenames are matched
    assert!(vandam::heuristics::is_cat_like_or_shell("/bin/cat", ""));
    assert!(vandam::heuristics::is_cat_like_or_shell("/usr/bin/grep", ""));
    assert!(vandam::heuristics::is_cat_like_or_shell("/bin/bash", ""));
    assert!(!vandam::heuristics::is_cat_like_or_shell("/usr/sbin/nginx", ""));
}


