use std::path::Path;
use std::sync::Arc;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use crate::heuristics::HeuristicsEngine;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", content = "payload")]
pub enum CliRequest {
    Status,
    ReloadRules,
    ReleaseContainment { pid: u32 },
    ListProcesses,
    ListRules,
    TrustOnce { pid: u32 },
    AllowProcessTree { pid: u32 },
    KillProcessTree { pid: u32 },
    DenyProcessTree { pid: u32 },
    Subscribe,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status", content = "payload")]
pub enum CliResponse {
    Success(serde_json::Value),
    Error(String),
}

pub struct ControlServer {
    socket_path: String,
    engine: Arc<HeuristicsEngine>,
}

impl ControlServer {
    pub fn new(socket_path: &str, engine: Arc<HeuristicsEngine>) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            engine,
        }
    }

    #[cfg(unix)]
    pub async fn start(self) -> Result<(), std::io::Error> {
        let path = Path::new(&self.socket_path);

        // Remove old socket file if it exists
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        // Ensure parent directories exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(path)?;

        // Set secure permissions: root-only read/write
        let mut permissions = std::fs::metadata(path)?.permissions();
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o600);
        std::fs::set_permissions(path, permissions)?;

        println!("[Agent Control] Listening on Unix Domain Socket: {}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let engine = Arc::clone(&self.engine);
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, engine).await {
                            eprintln!("[Agent Control] Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[Agent Control] Failed to accept connection: {}", e);
                }
            }
        }
    }

    #[cfg(windows)]
    pub async fn start(self) -> Result<(), std::io::Error> {
        use tokio::net::windows::named_pipe::ServerOptions;

        let pipe_name = format!(r"\\.\pipe\kinnector-control");
        println!("[Agent Control] Listening on Named Pipe: {}", pipe_name);

        let mut first = true;
        loop {
            let server = match ServerOptions::new()
                .first_pipe_instance(first)
                .create(&pipe_name) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[Agent Control] Failed to create named pipe: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                };
            first = false;

            match server.connect().await {
                Ok(_) => {
                    let engine = Arc::clone(&self.engine);
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(server, engine).await {
                            eprintln!("[Agent Control] Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[Agent Control] Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_connection<S>(
        mut stream: S,
        engine: Arc<HeuristicsEngine>,
    ) -> Result<(), Box<dyn std::error::Error>> 
    where S: AsyncReadExt + AsyncWriteExt + Unpin
    {
        // Read request from socket
        let mut buffer = Vec::new();
        let mut tmp = [0u8; 1024];
        
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break; // EOF
            }
            buffer.extend_from_slice(&tmp[..n]);
            
            // Check if we can parse the JSON yet (non-blocking attempt)
            if let Ok(_req) = serde_json::from_slice::<CliRequest>(&buffer) {
                break;
            }
        }

        if buffer.is_empty() {
            return Ok(());
        }

        let request: CliRequest = match serde_json::from_slice(&buffer) {
            Ok(req) => req,
            Err(e) => {
                let resp = CliResponse::Error(format!("Invalid request format: {}", e));
                let resp_bytes = serde_json::to_vec(&resp)?;
                stream.write_all(&resp_bytes).await?;
                return Ok(());
            }
        };

        if let CliRequest::Subscribe = &request {
            let mut rx = engine.alert_tx.subscribe();
            let resp = CliResponse::Success(serde_json::json!({ "message": "Subscription active" }));
            if let Ok(resp_bytes) = serde_json::to_vec(&resp) {
                let _ = stream.write_all(&resp_bytes).await;
                let _ = stream.write_all(b"\n").await;
            }
            while let Ok(alert) = rx.recv().await {
                if let Ok(alert_bytes) = serde_json::to_vec(&alert) {
                    if stream.write_all(&alert_bytes).await.is_err() ||
                       stream.write_all(b"\n").await.is_err() {
                        break; // Connection closed
                    }
                }
            }
            return Ok(());
        }

        // Process request
        let response = match request {
            CliRequest::Status => {
                let active_processes = engine.process_map.iter().filter(|e| !e.value().terminated).count();
                
                let config_lock = engine.config.read().unwrap();
                let rules_version = config_lock.version();
                let rules_timestamp = config_lock.epoch_timestamp();

                CliResponse::Success(serde_json::json!({
                    "running": true,
                    "daemon_version": env!("CARGO_PKG_VERSION"),
                    "rules_version": rules_version,
                    "rules_timestamp": rules_timestamp,
                    "active_processes": active_processes,
                    "lsm_active": unsafe { crate::ffi::is_lsm_active() }
                }))
            }
            CliRequest::ReloadRules => {
                #[cfg(unix)]
                let rules_path = "/etc/kinnector/rules.db";
                #[cfg(windows)]
                let rules_path = "C:\\ProgramData\\Kinnector\\rules.db";
                let public_key = [25, 127, 107, 35, 225, 108, 133, 50, 198, 171, 200, 56, 250, 205, 94, 167, 137, 190, 12, 118, 178, 146, 3, 52, 3, 155, 250, 139, 61, 54, 141, 97];
                
                match kinnector_config::ConfigManager::load(rules_path, &public_key) {
                    Ok(mgr) => {
                        let mgr_arc = Arc::new(mgr);
                        // Swap the heuristics config
                        {
                            let mut config_lock = engine.config.write().unwrap();
                            *config_lock = mgr_arc.clone();
                        }
                        
                        // Register new sensitive files in kernel via FFI
                        let sensitive_files = mgr_arc.sensitive_files();
                        for (path_str, category_flags) in sensitive_files {
                            if let Ok(metadata) = std::fs::metadata(&path_str) {
                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::MetadataExt;
                                    let inode = metadata.ino();
                                    println!("[Agent Control] Dynamically registering sensitive file: {} (Inode: {}, Category Flags: {:#x})", path_str, inode, category_flags);
                                    unsafe {
                                        crate::ffi::add_sensitive_inode(inode, category_flags);
                                    }
                                }
                            }
                        }

                        // Register new protected directories in kernel via FFI
                        let protected_dirs = mgr_arc.protected_application_directories();
                        for path_str in protected_dirs.keys() {
                            if let Ok(metadata) = std::fs::metadata(path_str) {
                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::MetadataExt;
                                    let inode = metadata.ino();
                                    println!("[Agent Control] Dynamically registering protected directory: {} (Inode: {})", path_str, inode);
                                    unsafe {
                                        crate::ffi::add_sensitive_inode(inode, 0x08); // CAT_APP_DATA
                                    }
                                }
                            }
                        }
                        
                        CliResponse::Success(serde_json::json!({ "message": "Rules database reloaded successfully" }))
                    }
                    Err(e) => {
                        CliResponse::Error(format!("Failed to load new rules database: {}", e))
                    }
                }
            }
            CliRequest::ReleaseContainment { pid } => {
                match engine.release_process_tree(pid) {
                    Ok(()) => CliResponse::Success(serde_json::json!({ "message": format!("Process tree starting at PID {} resumed", pid) })),
                    Err(e) => CliResponse::Error(e),
                }
            }
            CliRequest::ListProcesses => {
                let mut list = Vec::new();
                for entry in engine.process_map.iter() {
                    let state = entry.value();
                    if state.terminated {
                        continue;
                    }
                    let contained = state.pending_network_connect ||
                        (state.is_untrusted && state.category_flags != 0) ||
                        (state.is_naked_tty && state.category_flags.count_ones() >= 3) ||
                        (state.category_flags.count_ones() >= 2);

                    list.push(serde_json::json!({
                        "pid": state.key.pid,
                        "ppid": state.ppid,
                        "exe": state.image_path,
                        "cmdline": state.command_line,
                        "category_flags": state.category_flags,
                        "contained": contained,
                        "untrusted": state.is_untrusted,
                        "naked_tty": state.is_naked_tty,
                        "env": crate::heuristics::get_process_env_all(state.key.pid),
                    }));
                }
                CliResponse::Success(serde_json::json!({ "processes": list }))
            }
            CliRequest::ListRules => {
                let config_lock = engine.config.read().unwrap();
                let mut list = Vec::new();
                for (path, flags) in config_lock.sensitive_files() {
                    list.push(serde_json::json!({
                        "path": path,
                        "category_flags": flags
                    }));
                }
                CliResponse::Success(serde_json::json!({ "rules": list }))
            }
            CliRequest::TrustOnce { pid } => {
                let mut found = false;
                for mut entry in engine.process_map.iter_mut() {
                    if entry.key().pid == pid {
                        let state = entry.value_mut();
                        state.category_flags = 0;
                        state.pending_network_connect = false;
                        state.is_untrusted = false;
                        found = true;
                        break;
                    }
                }
                if found {
                    CliResponse::Success(serde_json::json!({ "message": format!("Temporary trust bypass granted for PID {}", pid) }))
                } else {
                    CliResponse::Error(format!("PID {} not found in active telemetry state", pid))
                }
            }
            CliRequest::AllowProcessTree { pid } => {
                let mut target_key = None;
                let mut image_path = String::new();
                for entry in engine.process_map.iter() {
                    if entry.key().pid == pid && !entry.value().terminated {
                        target_key = Some(entry.key().clone());
                        image_path = entry.value().image_path.clone();
                        break;
                    }
                }

                if let Some(_key) = target_key {
                    if let Ok(metadata) = std::fs::metadata(&image_path) {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            let inode = metadata.ino();
                            unsafe {
                                crate::ffi::add_trusted_exec_inode(inode, 2);
                            }
                        }
                        crate::trust_cache::add_to_user_allowlist(std::path::Path::new(&image_path));
                    }

                    match engine.release_process_tree(pid) {
                        Ok(()) => CliResponse::Success(serde_json::json!({ "message": format!("Process tree starting at PID {} permanently allowed and resumed", pid) })),
                        Err(e) => CliResponse::Error(e),
                    }
                } else {
                    CliResponse::Error(format!("PID {} not found in active telemetry state", pid))
                }
            }
            CliRequest::KillProcessTree { pid } => {
                match engine.kill_process_tree(pid) {
                    Ok(()) => CliResponse::Success(serde_json::json!({ "message": format!("Process tree starting at PID {} terminated", pid) })),
                    Err(e) => CliResponse::Error(e),
                }
            }
            CliRequest::DenyProcessTree { pid } => {
                let mut target_key = None;
                let mut image_path = String::new();
                for entry in engine.process_map.iter() {
                    if entry.key().pid == pid && !entry.value().terminated {
                        target_key = Some(entry.key().clone());
                        image_path = entry.value().image_path.clone();
                        break;
                    }
                }

                if let Some(_key) = target_key {
                    crate::trust_cache::add_to_user_denylist(std::path::Path::new(&image_path));

                    match engine.kill_process_tree(pid) {
                        Ok(()) => CliResponse::Success(serde_json::json!({ "message": format!("Process tree starting at PID {} registered in persistent user denylist and terminated", pid) })),
                        Err(e) => CliResponse::Error(e),
                    }
                } else {
                    CliResponse::Error(format!("PID {} not found in active telemetry state", pid))
                }
            }
            CliRequest::Subscribe => unreachable!(),
        };

        // Write response back
        let resp_bytes = serde_json::to_vec(&response)?;
        stream.write_all(&resp_bytes).await?;
        stream.flush().await?;

        Ok(())
    }
}
