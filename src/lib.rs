pub mod types;
pub mod ipc;
pub mod heuristics;
pub mod ffi;
pub mod control;
pub mod trust_cache;
pub mod tty_listener;
pub mod yara_scanner;
pub mod sigma_engine;
pub mod os_utils;

use tokio::sync::mpsc;
use std::time::Duration;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::path::Path;
use notify::{Watcher, RecursiveMode, EventKind};
use crate::ipc::IpcServer;
use crate::heuristics::HeuristicsEngine;
use crate::control::ControlServer;

pub async fn run_agent() -> Result<(), Box<dyn std::error::Error>> {
    println!("====================================================");
    println!("           Kinnector EDR Agent Daemon               ");
    println!("====================================================");

    // Socket configuration (standard agent paths)
    #[cfg(unix)]
    let socket_path = "/var/run/kinnector/telemetry.sock";
    #[cfg(windows)]
    let socket_path = "\\\\.\\pipe\\kinnector-telemetry";
    
    let auth_token = "super-secret-agent-token-12345";
    // Resolve BPF object path (check standard packaged location first, then fallback to workspace)
    #[cfg(unix)]
    let bpf_path = {
        let bpf_packaged_path = "/usr/lib/kinnector/kinnector.bpf.o";
        if std::path::Path::new(bpf_packaged_path).exists() {
            bpf_packaged_path
        } else {
            "/home/user/Documents/kinnector/core/build/kinnector.bpf.o"
        }
    };
    #[cfg(windows)]
    let bpf_path = "";

    // Setup event queue channels
    let (event_tx, mut event_rx) = mpsc::channel(4096);

    // Initialize Rules Configuration Manager
    #[cfg(unix)]
    let rules_path = "/etc/kinnector/rules.db";
    #[cfg(windows)]
    let rules_path = "C:\\ProgramData\\Kinnector\\rules.db";
    
    let public_key = [25, 127, 107, 35, 225, 108, 133, 50, 198, 171, 200, 56, 250, 205, 94, 167, 137, 190, 12, 118, 178, 146, 3, 52, 3, 155, 250, 139, 61, 54, 141, 97]; // Derived prototype verifying public key
    let config_manager = match kinnector_config::ConfigManager::load(rules_path, &public_key) {
        Ok(mgr) => {
            println!("[Agent] Rules database loaded successfully from {}", rules_path);
            std::sync::Arc::new(mgr)
        }
        Err(e) => {
            println!("[Agent] Warning: Failed to load rules database: {}. Using default built-in policy.", e);
            std::sync::Arc::new(kinnector_config::ConfigManager::load_defaults())
        }
    };

    // Initialize Heuristics Detection Engine with Config Manager
    let engine = HeuristicsEngine::new(config_manager.clone());
    let engine_ref = std::sync::Arc::new(engine);

    // Spawn TTL purging loop in the background to clean up finished process states
    let engine_purge = engine_ref.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            engine_purge.purge_expired_states();
        }
    });

    // Spawn ingestion consumer loop inside a dedicated background OS thread
    let engine_consume = engine_ref.clone();
    std::thread::spawn(move || {
        println!("[Agent] Dedicated OS-level background thread for telemetry ingestion active.");
        while let Some(event) = event_rx.blocking_recv() {
            engine_consume.handle_event(event);
        }
    });

    // Spawn inotify configuration hot-reload loop
    let engine_reload = engine_ref.clone();
    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::channel(16);

        let mut watcher = match notify::recommended_watcher(move |res| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("[Agent] Failed to create recommended watcher: {}", e);
                return;
            }
        };

        // Watch the configuration directory for updates
        #[cfg(unix)]
        let rules_dir = Path::new("/etc/kinnector");
        #[cfg(windows)]
        let rules_dir = Path::new("C:\\ProgramData\\Kinnector");
        
        if let Err(e) = watcher.watch(rules_dir, RecursiveMode::NonRecursive) {
            eprintln!("[Agent] Failed to watch {}: {}", rules_dir.display(), e);
            return;
        }

        println!("[Agent] Real-time rules hot-reloader active on: {}", rules_dir.display());

        // Process file system events
        while let Some(event) = rx.recv().await {
            let mut should_reload = false;
            for path in event.paths {
                if path.file_name().and_then(|f| f.to_str()) == Some("rules.db") {
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) => {
                            should_reload = true;
                            break;
                        }
                        _ => {}
                    }
                }
            }

            if should_reload {
                println!("[Agent] rules.db change detected. Reloading dynamic policies...");
                tokio::time::sleep(Duration::from_millis(100)).await;

                #[cfg(unix)]
                let rules_path = "/etc/kinnector/rules.db";
                #[cfg(windows)]
                let rules_path = "C:\\ProgramData\\Kinnector\\rules.db";
                let public_key = [25, 127, 107, 35, 225, 108, 133, 50, 198, 171, 200, 56, 250, 205, 94, 167, 137, 190, 12, 118, 178, 146, 3, 52, 3, 155, 250, 139, 61, 54, 141, 97];

                match kinnector_config::ConfigManager::load(rules_path, &public_key) {
                    Ok(mgr) => {
                        let mgr_arc = Arc::new(mgr);
                        {
                            let mut config_lock = engine_reload.config.write().unwrap();
                            *config_lock = mgr_arc.clone();
                        }

                        let sensitive_files = mgr_arc.sensitive_files();
                        for (path_str, category_flags) in sensitive_files {
                            if let Ok(metadata) = std::fs::metadata(&path_str) {
                                #[cfg(unix)]
                                {
                                    let inode = metadata.ino();
                                    println!("[Agent Reloader] Dynamically registering sensitive file: {} (Inode: {}, Category Flags: {:#x})", path_str, inode, category_flags);
                                    unsafe {
                                        ffi::add_sensitive_inode(inode, category_flags);
                                    }
                                }
                                #[cfg(windows)]
                                {
                                    println!("[Agent Reloader] Registering sensitive file path: {} (Category Flags: {:#x})", path_str, category_flags);
                                }
                            }
                        }
                        println!("[Agent Reloader] Hot-reload completed successfully.");
                    }
                    Err(e) => {
                        eprintln!("[Agent Reloader] Hot-reload error: failed to reload rules database: {}", e);
                    }
                }
            }
        }
        
        drop(watcher);
    });

    // Initialize & start C++ Telemetry Engine via FFI
    let bpf_path_c = std::ffi::CString::new(bpf_path)?;
    let socket_path_c = std::ffi::CString::new(socket_path)?;
    let auth_token_c = std::ffi::CString::new(auth_token)?;

    println!("[Agent] Initializing low-level C++ telemetry engine...");
    let init_success = unsafe {
        ffi::initialize_telemetry_engine(
            bpf_path_c.as_ptr(),
            socket_path_c.as_ptr(),
            auth_token_c.as_ptr(),
        )
    };

    if !init_success {
        eprintln!("[Agent] Failed to initialize C++ telemetry engine via FFI!");
        return Err("Telemetry FFI init failed".into());
    }

    // Initialize Adaptive Inode Trust Cache and enable blocking mode
    trust_cache::initialize_trust_cache(&config_manager);

    println!("[Agent] Starting low-level C++ telemetry engine...");
    let start_success = unsafe { ffi::start_telemetry_engine() };
    if !start_success {
        eprintln!("[Agent] Failed to start C++ telemetry engine!");
        return Err("Telemetry FFI start failed".into());
    }

    let is_lsm = unsafe { ffi::is_lsm_active() };
    if is_lsm {
        println!("[Agent] LSM Mode is ACTIVE. Operating with kernel-level security, stability, and maximum performance.");
    } else {
        println!("\n[WARNING] ==================================================================");
        println!("[WARNING] BPF LSM IS NOT ENABLED ON THIS SYSTEM!");
        println!("[WARNING] The agent is running in USER-MODE fallback detection/enforcement.");
        println!("[WARNING] Running in user-mode is prone to race conditions (TOCTOU) and timing bugs.");
        println!("[WARNING] For optimal security, stability, and performance, please enable BPF LSM!");
        println!("[WARNING] ==================================================================\n");
    }

    // Register sensitive files and protected directories from configuration
    {
        let sensitive_files = config_manager.sensitive_files();
        for (path_str, category_flags) in sensitive_files {
            if let Ok(metadata) = std::fs::metadata(&path_str) {
                #[cfg(unix)]
                {
                    let inode = metadata.ino();
                    println!("[Agent] Registering sensitive file: {} (Inode: {}, Category Flags: {:#x})", path_str, inode, category_flags);
                    unsafe {
                        ffi::add_sensitive_inode(inode, category_flags);
                    }
                }
                #[cfg(windows)]
                {
                    println!("[Agent] Registering sensitive file path: {} (Category Flags: {:#x})", path_str, category_flags);
                }
            }
        }

        let protected_dirs = config_manager.protected_application_directories();
        for path_str in protected_dirs.keys() {
            if let Ok(metadata) = std::fs::metadata(path_str) {
                #[cfg(unix)]
                {
                    let inode = metadata.ino();
                    println!("[Agent] Registering protected directory: {} (Inode: {}, Category: CAT_APP_DATA)", path_str, inode);
                    unsafe {
                        ffi::add_sensitive_inode(inode, 0x08);
                    }
                }
                #[cfg(windows)]
                {
                    println!("[Agent] Registering protected directory path: {}", path_str);
                }
            }
        }
    }

    // Register a Ctrl+C handler for clean shutdown
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("failed to listen for event");
        println!("\n[Agent] Shutdown signal received. Stopping telemetry engine...");
        unsafe {
            ffi::stop_telemetry_engine();
        }
        std::process::exit(0);
    });

    // Initialize & start Control Socket Server in the background
    #[cfg(unix)]
    let control_socket_path = "/var/run/kinnector/control.sock";
    #[cfg(windows)]
    let control_socket_path = "\\\\.\\pipe\\kinnector-control";
    
    let control_server = ControlServer::new(control_socket_path, engine_ref.clone());
    tokio::spawn(async move {
        if let Err(e) = control_server.start().await {
            eprintln!("[Agent] Failed to start control server: {}", e);
        }
    });

    // Initialize & start TtyListener in the background
    #[cfg(unix)]
    {
        let tty_socket_path = "/var/run/kinnector/tty_telemetry.sock";
        let tty_server = tty_listener::TtyListener::new(tty_socket_path);
        tokio::spawn(async move {
            if let Err(e) = tty_server.start().await {
                eprintln!("[Agent] Failed to start TTY listener: {}", e);
            }
        });
    }

    // Initialize & start Unix Domain Socket Server (Blocks main thread)
    let server = IpcServer::new(socket_path, auth_token, event_tx);
    server.start().await?;

    Ok(())
}
