#![allow(dead_code)]
use std::sync::Arc;
use std::collections::HashSet;
use dashmap::DashMap;
use chrono::{DateTime, Utc, Duration};
use crate::types::{TelemetryEventRaw, EventType, TelemetryHeader, ProcessCreateDetails, NetworkConnectDetails, FileReadDetails, RegistryWriteDetails, ClipboardWriteDetails};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Debug, Clone)]
pub struct ProcessState {
    pub key: ProcessKey,
    pub ppid: u32,
    pub real_parent_pid: u32,
    pub image_path: String,
    pub command_line: String,
    pub category_flags: u32,
    pub pending_network_connect: bool,
    pub terminated: bool,
    pub ttl_deadline: Option<DateTime<Utc>>,
    pub is_naked_tty: bool,
    pub is_untrusted: bool, // true if unsigned/not allowlisted
    pub is_install_context: bool,
    pub is_top_level_install: bool,
    pub install_root_pid: u32,
    pub depth: u32,
    pub unique_files_read: HashSet<String>,
}

pub struct HeuristicsEngine {
    pub process_map: Arc<DashMap<ProcessKey, ProcessState>>,
    pub children_map: Arc<DashMap<ProcessKey, HashSet<ProcessKey>>>,
    pub config: std::sync::RwLock<Arc<kinnector_config::ConfigManager>>,
    pub audit_mode: bool,
    pub alert_tx: tokio::sync::broadcast::Sender<crate::types::Alert>,
    pub yara_scanner: Arc<crate::yara_scanner::YaraScanner>,
    pub sigma_engine: Arc<crate::sigma_engine::SigmaRulesEngine>,
    pub tokio_handle: tokio::runtime::Handle,
    pub path_velocity_map: Arc<DashMap<String, (HashSet<String>, std::time::Instant)>>,
}

impl HeuristicsEngine {
    pub fn new(config: Arc<kinnector_config::ConfigManager>) -> Self {
        let audit_mode = std::env::var("KINNECTOR_AUDIT")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        if audit_mode {
            println!("[Heuristics] Active Mode: AUDIT / COLLECT (No prevention containment will be executed)");
        } else {
            println!("[Heuristics] Active Mode: PREVENTION / ENFORCEMENT");
        }
        let (alert_tx, _) = tokio::sync::broadcast::channel(100);
        let yara_scanner = Arc::new(crate::yara_scanner::YaraScanner::new());
        let sigma_engine = Arc::new(crate::sigma_engine::SigmaRulesEngine::new());
        let tokio_handle = tokio::runtime::Handle::current();
        Self {
            process_map: Arc::new(DashMap::new()),
            children_map: Arc::new(DashMap::new()),
            config: std::sync::RwLock::new(config),
            audit_mode,
            alert_tx,
            yara_scanner,
            sigma_engine,
            tokio_handle,
            path_velocity_map: Arc::new(DashMap::new()),
        }
    }

    pub fn handle_event(self: &Arc<Self>, raw: TelemetryEventRaw) {
        let header = raw.header;
        let event_type = header.event_type;
        let source = header.source;
        let pid = header.pid;
        println!(
            "[Heuristics] Received event: Type={:?}, Source={:?}, PID={}",
            event_type, source, pid
        );
        
        match event_type {
            EventType::ProcessCreate => {
                let details = unsafe {
                    std::ptr::read_unaligned(raw.details_buffer.as_ptr() as *const ProcessCreateDetails)
                };
                self.process_create(header, details);
            }
            EventType::ProcessStop => {
                self.process_stop(header);
            }
            EventType::FileRead => {
                let details = unsafe {
                    std::ptr::read_unaligned(raw.details_buffer.as_ptr() as *const FileReadDetails)
                };
                self.file_read(header, details);
            }
            EventType::FileWrite => {
                let details = unsafe {
                    std::ptr::read_unaligned(raw.details_buffer.as_ptr() as *const crate::types::FileWriteDetails)
                };
                self.file_write(header, details);
            }
            EventType::NetworkConnect => {
                let details = unsafe {
                    std::ptr::read_unaligned(raw.details_buffer.as_ptr() as *const NetworkConnectDetails)
                };
                self.network_connect(header, details);
            }
            EventType::FileOpen => {
                let details = unsafe {
                    std::ptr::read_unaligned(raw.details_buffer.as_ptr() as *const crate::types::FileOpenDetails)
                };
                self.file_open(header, details);
            }
            EventType::Dup2 => {
                let details = unsafe {
                    std::ptr::read_unaligned(raw.details_buffer.as_ptr() as *const crate::types::Dup2Details)
                };
                self.dup2(header, details);
            }
            EventType::RegistryWrite => {
                let details = unsafe {
                    std::ptr::read_unaligned(raw.details_buffer.as_ptr() as *const RegistryWriteDetails)
                };
                self.registry_write(header, details);
            }
            EventType::ClipboardWrite => {
                let details = unsafe {
                    std::ptr::read_unaligned(raw.details_buffer.as_ptr() as *const ClipboardWriteDetails)
                };
                self.clipboard_write(header, details);
            }
            EventType::PtraceAttach => {
                // Fix 8/11: PtraceAttach is now emitted on every ptrace attempt (not just blocks).
                let details = unsafe {
                    std::ptr::read_unaligned(raw.details_buffer.as_ptr() as *const crate::types::BpfPtraceAttachDetails)
                };
                self.ptrace_attach(header, details);
            }
            EventType::MemoryMap | EventType::MemoryProtect => {
                // Fix 6: MemoryProtect carries file_inode for file-backed VMAs.
                // MemoryMap is for anonymous regions (pre-existing behaviour).
                let details = unsafe {
                    std::ptr::read_unaligned(raw.details_buffer.as_ptr() as *const crate::types::MemoryMapBpfDetails)
                };
                self.memory_protect(header, details, event_type == EventType::MemoryProtect);
            }
            EventType::ImageLoad => {
                // Fix 10: SO/DLL load telemetry from lsm/mmap_file.
                let details = unsafe {
                    std::ptr::read_unaligned(raw.details_buffer.as_ptr() as *const crate::types::BpfImageLoadDetails)
                };
                self.image_load(header, details);
            }
            _ => {}
        }
    }

    fn process_create(self: &Arc<Self>, header: TelemetryHeader, details: ProcessCreateDetails) {
        let child_pid = details.child_pid;
        let real_parent_pid = details.real_parent_pid;

        let child_path = String::from_utf8_lossy(&details.child_image_path)
            .trim_end_matches('\0')
            .to_string();
        let child_cmd = String::from_utf8_lossy(&details.child_command_line)
            .trim_end_matches('\0')
            .to_string();

        let key = ProcessKey {
            pid: child_pid,
            start_time: header.timestamp_ns, // simple start time using timestamp
        };

        // Determine trust status (mock logic: check if running from volatile path like /tmp)
        let mut is_untrusted = false; // We rely on ZoneIdentifier MOTW in reality

        #[cfg(windows)]
        {
            let child_lower_exe = child_path.to_lowercase();
            let cmd_lower = child_cmd.to_lowercase();
            let config_guard = self.config.read().unwrap();
            let is_browser = config_guard.browser_executables().iter().any(|b| child_lower_exe.ends_with(&b.to_lowercase()));
            if is_browser {
                if cmd_lower.contains("--user-data-dir") || cmd_lower.contains("--profile-directory") {
                    let is_non_standard = cmd_lower.contains("users\\public") || cmd_lower.contains("temp") || cmd_lower.contains("desktop") || cmd_lower.contains("appdata\\local\\temp");
                    if is_non_standard {
                        println!("[EDR ALERT] hVNC Profile Redirection detected on browser PID {}!", child_pid);
                        is_untrusted = true;
                        self.terminate_threat_pkm(&key, "hVNC browser profile redirection bypass detected", "browser_db", &child_path);
                        return;
                    }
                }
            }

            let is_interpreter = config_guard.script_interpreters().iter().any(|i| {
                let i_lower = i.to_lowercase();
                child_lower_exe.ends_with(&i_lower) || child_lower_exe.ends_with(&format!("{}.exe", i_lower))
            });

            if is_interpreter {
                let has_inline_flag = cmd_lower.contains(" -c ") || cmd_lower.contains(" -command ") 
                    || cmd_lower.contains(" -encodedcommand ") || cmd_lower.contains(" /c ") 
                    || cmd_lower.contains(" -e ") || cmd_lower.contains(" -r ") || cmd_lower.contains(" -eval ");
                if has_inline_flag {
                    println!("[EDR ALERT] Interpreter inline execution demotion triggered for PID {}!", child_pid);
                    is_untrusted = true;
                }
            }
        }
        
        #[cfg(unix)]
        {
            is_untrusted = child_path.starts_with("/tmp/") || child_path.starts_with("/dev/shm/");

            // Fix 12: Detect anonymous/memfd execution (Process Ghosting / Doppelgänging).
            // memfd_create + execveat produces a child_path of "" or "/proc/self/fd/<N>" or "memfd:<name>".
            // Fire an explicit alert immediately rather than waiting for the first sensitive file access.
            if child_path.is_empty()
                || child_path.starts_with("/proc/self/fd/")
                || child_path.starts_with("/proc/")
                    && child_path.contains("/fd/")
                || child_path.starts_with("memfd:")
            {
                println!(
                    "[Ghosting Alert] PID {} executed from anonymous/memfd region: '{}' — possible process ghosting or doppelgänging",
                    child_pid, child_path
                );
                is_untrusted = true;
                self.write_structured_alert(
                    child_pid,
                    "ALERT",
                    "anonymous_exec",
                    &child_path,
                    "LOGGED",
                    &format!(
                        "Process PID {} executed from anonymous/memfd region '{}' — possible process ghosting",
                        child_pid, child_path
                    ),
                );
            }
        }
        
        if self.config.read().unwrap().is_path_excluded(std::path::Path::new(&child_path)) {
            is_untrusted = false;
        }
        let signer = kinnector_config::SignerInfo {
            signer_name: "Google LLC".to_string(), // In production, we'd extract this from the ELF's signature
            team_id: Some("EQHXZ8M8AV".to_string()),
            is_signed: true,
        };
        if self.config.read().unwrap().is_trusted_vendor(&signer) {
            is_untrusted = false;
        }

        #[cfg(unix)]
        {
            let config_guard = self.config.read().unwrap();
            let is_gui_app = config_guard.hvnc_monitored_gui_apps().iter().any(|app| {
                let app_lower = app.to_lowercase();
                if app_lower.starts_with('/') {
                    child_path.ends_with(&app_lower)
                } else {
                    child_path.contains(&app_lower)
                }
            });

            if is_gui_app {
                let (active_display, active_wayland) = get_active_session_context(&config_guard)
                    .map(|ctx| (ctx.display, ctx.wayland_display))
                    .unwrap_or((None, None));
                let child_display = get_process_env(child_pid, "DISPLAY");
                let child_wayland = get_process_env(child_pid, "WAYLAND_DISPLAY");

                let display_mismatch = match (&active_display, &child_display) {
                    (Some(active), Some(child)) => active != child,
                    (None, Some(child)) => child.contains("99") || child.contains("1"), // headless display indicators
                    _ => false,
                };

                let wayland_mismatch = match (&active_wayland, &child_wayland) {
                    (Some(active), Some(child)) => active != child,
                    _ => false,
                };

                if display_mismatch || wayland_mismatch {
                    println!(
                        "[hVNC Heuristic] hVNC/Display hijacking detected! PID {} launched on display {:?}/{:?} (Active user display is {:?}/{:?})",
                        child_pid, child_display, child_wayland, active_display, active_wayland
                    );
                    is_untrusted = true;
                }
            }
        }

        let config_guard = self.config.read().unwrap();
        let child_lower = child_path.to_lowercase();
        let matches_interpreter = config_guard.script_interpreters().iter().any(|i| {
            let i_lower = i.to_lowercase();
            child_lower.contains(&i_lower)
        });
        let matches_shell = config_guard.interactive_shells().iter().any(|s| {
            let s_lower = s.to_lowercase();
            child_lower.ends_with(&s_lower) || child_lower.contains(&format!("powershell")) || child_lower.contains(&format!("pwsh"))
        });
        let (is_interpreter_or_shell, is_shell) = (matches_interpreter || matches_shell, matches_shell);

        let is_stdin_tty = if let Ok(target) = std::fs::read_link(format!("/proc/{}/fd/0", child_pid)) {
            let target_str = target.to_string_lossy();
            target_str.starts_with("/dev/pts/") || target_str.starts_with("/dev/tty")
        } else {
            false
        };

        let has_inline_flags = child_cmd.contains(" -c")
            || child_cmd.contains(" -e")
            || child_cmd.contains(" -r")
            || child_cmd.contains(" --eval")
            || child_cmd.contains(" -Command");

        if is_interpreter_or_shell && (has_inline_flags || !is_stdin_tty) {
            println!(
                "[Demotion Heuristic] Piped or inline script execution detected for PID {}! Marking as untrusted.",
                child_pid
            );
            is_untrusted = true;
        }

        // Determine naked TTY status
        let is_naked_tty = is_shell && is_stdin_tty && !has_inline_flags;

        // With Zero-Tolerance Vendor Ownership, threshold is strictly 1 in eBPF map
        let threshold = 1;

        let mut is_parent_install = false;
        let mut install_root_pid = 0u32;
        let mut depth = 0u32;

        for entry in self.process_map.iter() {
            if entry.key().pid == real_parent_pid && !entry.value().terminated {
                is_parent_install = entry.value().is_install_context;
                install_root_pid = entry.value().install_root_pid;
                depth = entry.value().depth + 1;
                break;
            }
        }

        let child_lower = child_path.to_lowercase();
        let is_child_install = config_guard.installer_binaries().iter().any(|kw| {
            let kw_lower = kw.to_lowercase();
            child_lower == kw_lower || child_lower.ends_with(&format!("/{}", kw_lower)) || child_lower.ends_with(&format!("\\{}", kw_lower))
        });

        let is_top_level_install = is_child_install && !is_parent_install;
        let final_install_root = if is_top_level_install {
            child_pid
        } else {
            install_root_pid
        };
        let is_install_context = is_child_install || is_parent_install;

        unsafe {
            crate::ffi::update_process_threshold(child_pid, header.timestamp_ns, threshold);
        }

        let mut state = ProcessState {
            key: key.clone(),
            ppid: header.pid,
            real_parent_pid,
            image_path: child_path.clone(),
            command_line: child_cmd.clone(),
            category_flags: 0,
            pending_network_connect: false,
            terminated: false,
            ttl_deadline: None,
            is_naked_tty,
            is_untrusted,
            is_install_context,
            is_top_level_install,
            install_root_pid: final_install_root,
            depth,
            unique_files_read: HashSet::new(),
        };

        // Fix 2: Track and ENFORCE PPID Spoofing (Heuristic X).
        // Previously this was log-only; now it demotes the process to Untrusted and fires an alert.
        if state.real_parent_pid != state.ppid {
            println!(
                "[Heuristic X] PPID Spoofing detected! PID {} claims parent {}, but actual creator is {}",
                state.key.pid, state.ppid, state.real_parent_pid
            );
            // Demote to Untrusted so all downstream heuristics treat this process with maximum suspicion.
            state.is_untrusted = true;
            self.write_structured_alert(
                child_pid,
                "ALERT",
                "ppid_spoof",
                "",
                if self.audit_mode { "LOGGED" } else { "CONTAINED" },
                &format!(
                    "PPID spoofing detected: PID {} claims parent PID {} but real kernel creator is PID {}",
                    child_pid, state.ppid, state.real_parent_pid
                ),
            );
        }

        // Register process and children relationships
        self.process_map.insert(key.clone(), state);

        let parent_key = ProcessKey {
            pid: header.pid,
            start_time: 0, // start time wild-card for simplicity in lookup
        };
        self.children_map.entry(parent_key).or_default().insert(key.clone());

        // 3. Dynamic YARA file scan for Untrusted processes
        if is_untrusted {
            let scanner = self.yara_scanner.clone();
            let engine = Arc::clone(self);
            let path_buf = std::path::PathBuf::from(&child_path);
            let path_str = child_path.clone();
            let key_clone = key.clone();

            self.tokio_handle.spawn(async move {
                if scanner.scan_file(path_buf).await {
                    engine.suspend_process_tree(&key_clone, "YARA rule matched on execution", "malware_pattern", &path_str);
                }
            });
        }

        // 4. Sigma rules evaluation check
        let mut fields = std::collections::HashMap::new();
        fields.insert("Image".to_string(), child_path.clone());
        fields.insert("CommandLine".to_string(), child_cmd.clone());
        let p_pid = header.pid;
        if let Ok(parent_path) = std::fs::read_link(format!("/proc/{}/exe", p_pid)) {
            fields.insert("ParentImage".to_string(), parent_path.to_string_lossy().to_string());
        }

        let sigma_event = crate::sigma_engine::SigmaEvent {
            category: "process_creation".to_string(),
            fields,
        };

        if let Some(rule) = self.sigma_engine.evaluate(&sigma_event) {
            println!("[Sigma Alert] Rule matched: {} ({})", rule.title, rule.id);
            self.suspend_process_tree(&key, &format!("Sigma correlation matched: {}", rule.title), "sigma_alert", &child_path);
        }
    }

    fn file_write(self: &Arc<Self>, header: TelemetryHeader, details: crate::types::FileWriteDetails) {
        let file_path = String::from_utf8_lossy(&details.file_path)
            .trim_end_matches('\0')
            .to_string();

        let mut process_key = None;
        let event_pid = header.pid;
        for entry in self.process_map.iter() {
            if entry.key().pid == event_pid && !entry.value().terminated {
                process_key = Some(entry.key().clone());
                break;
            }
        }

        let key = match process_key {
            Some(k) => k,
            None => {
                println!(
                    "[State machine] Process PID {} wrote file: {}",
                    event_pid, file_path
                );
                return;
            }
        };

        let mut is_install = false;
        if let Some(state) = self.process_map.get(&key) {
            is_install = state.is_install_context;
        }

        // Protected Directory Check (Cross-platform HIPS directory shielding)
        if let Some(state) = self.process_map.get(&key) {
            let path_lower = file_path.to_lowercase();
            let config_guard = self.config.read().unwrap();
            let protected_dirs = config_guard.protected_application_directories();
            
            let mut protected_dir_match = None;
            for dir_pattern in protected_dirs.keys() {
                let pattern_lower = dir_pattern.to_lowercase();
                let pattern_backslashes = pattern_lower.replace('/', "\\");
                if path_lower.contains(&pattern_lower) || path_lower.contains(&pattern_backslashes) {
                    protected_dir_match = Some(dir_pattern);
                    break;
                }
            }

            if let Some(dir_pattern) = protected_dir_match {
                let allowed_writer = protected_dirs.get(dir_pattern).unwrap().to_lowercase();
                let accessor_lower = state.image_path.to_lowercase();
                if !accessor_lower.contains(&allowed_writer) {
                    println!("[EDR ALERT] Unauthorized directory modification attempt in protected folder {} by {} (writing: {})!", dir_pattern, accessor_lower, path_lower);
                    self.terminate_threat_pkm(
                        &key,
                        &format!("Unauthorized directory modification attempt in protected folder by non-vendor process: {}", file_path),
                        "directory_hijack",
                        &file_path
                    );
                    return;
                }
            }
        }

        if is_install {
            let path_lower = file_path.to_lowercase();
            if path_lower.contains("/var/run/docker.sock") || path_lower.contains("/run/containerd/containerd.sock") {
                self.terminate_threat_pkm(
                    &key,
                    &format!("Package install process attempted to write to container runtime socket: {}", file_path),
                    "docker_socket_access",
                    &file_path
                );
                return;
            }

            let config_guard = self.config.read().unwrap();
            let is_profile = is_profile_like_path(&file_path, &config_guard);
            let is_persistence = is_profile || config_guard.persistence_paths().iter().any(|p| {
                let p_lower = p.to_lowercase();
                path_lower.contains(&p_lower)
            });

            if is_persistence {
                self.terminate_threat_pkm(
                    &key,
                    &format!("Package install process attempted to establish persistence: {}", file_path),
                    "persistence_path",
                    &file_path
                );
                return;
            }
        }

        println!(
            "[State machine] Process PID {} wrote file: {}",
            event_pid, file_path
        );
    }

    fn process_stop(&self, header: TelemetryHeader) {
        let event_pid = header.pid;
        let key = ProcessKey {
            pid: event_pid,
            start_time: 0, // simple wild-card for simplicity in lookup
        };

        let mut is_top_level = false;
        let mut target_key = None;
        for entry in self.process_map.iter() {
            if entry.key().pid == event_pid && !entry.value().terminated {
                if entry.value().is_top_level_install {
                    is_top_level = true;
                    target_key = Some(entry.key().clone());
                }
                break;
            }
        }

        if is_top_level {
            if let Some(key) = target_key {
                let process_map_clone = self.process_map.clone();
                let children_map_clone = self.children_map.clone();
                let alert_tx_clone = self.alert_tx.clone();
                let audit_mode = self.audit_mode;
                
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                    let mut pids_to_kill = Vec::new();
                    collect_descendants_static(&key, &children_map_clone, &mut pids_to_kill);

                    for child_pid in pids_to_kill {
                        let mut child_key = None;
                        for entry in process_map_clone.iter() {
                            if entry.key().pid == child_pid && !entry.value().terminated {
                                child_key = Some(entry.key().clone());
                                break;
                            }
                        }

                        if let Some(ck) = child_key {
                            let mut exe = String::new();
                            let mut cmd = String::new();
                            let mut ppid = 0;
                            if let Some(mut state) = process_map_clone.get_mut(&ck) {
                                state.terminated = true;
                                state.ttl_deadline = Some(Utc::now() + Duration::minutes(5));
                                exe = state.image_path.clone();
                                cmd = state.command_line.clone();
                                ppid = state.ppid;
                            }

                            if !exe.is_empty() {
                                println!("  [SupplyChain] Terminating orphaned process PID {}", child_pid);
                                if !audit_mode {
                                    crate::os_utils::terminate_process(child_pid);
                                }

                                let alert = crate::types::Alert {
                                    ts: Utc::now().to_rfc3339(),
                                    severity: "CRITICAL".to_string(),
                                    category: "persistence_path".to_string(),
                                    rule_path: "".to_string(),
                                    process: crate::types::ProcessInfo {
                                        pid: child_pid,
                                        ppid,
                                        exe,
                                        cmdline: cmd,
                                        env: std::collections::HashMap::new(),
                                    },
                                    action: "TERMINATED".to_string(),
                                    message: "Process continued running after package installation completed. Terminated process.".to_string(),
                                };
                                let _ = alert_tx_clone.send(alert);
                            }
                        }
                    }

                    if let Some(mut state) = process_map_clone.get_mut(&key) {
                        state.terminated = true;
                        state.ttl_deadline = Some(Utc::now() + Duration::minutes(5));
                    }
                });
            }
        } else {
            for entry in self.process_map.iter() {
                if entry.key().pid == event_pid && !entry.value().terminated {
                    let key = entry.key().clone();
                    drop(entry);
                    if let Some(mut state) = self.process_map.get_mut(&key) {
                        state.terminated = true;
                        state.ttl_deadline = Some(Utc::now() + Duration::minutes(5));
                        println!("[State machine] Process PID {} stopped, marked for TTL purge", key.pid);
                    }
                }
            }
        }
    }

    fn file_read(&self, header: TelemetryHeader, details: FileReadDetails) {
        let file_path = String::from_utf8_lossy(&details.file_path)
            .trim_end_matches('\0')
            .to_string();

        // 1. Resolve Category bitmask
        let config_guard = self.config.read().unwrap();
        if config_guard.is_path_excluded(std::path::Path::new(&file_path)) {
            return;
        }
        
        // Query category dynamically from sensitive files registry
        let mut resolved_cat = 0;
        for (p_str, cat) in config_guard.sensitive_files() {
            if file_path.contains(&p_str) || p_str.contains(&file_path) {
                resolved_cat = cat;
                break;
            }
        }
        if resolved_cat == 0 {
            return; // Not sensitive
        }
        let category = resolved_cat;

        // 2. Fetch Process State
        let mut process_key = None;
        for entry in self.process_map.iter() {
            if entry.key().pid == header.pid && !entry.value().terminated {
                process_key = Some(entry.key().clone());
                break;
            }
        }

        let key = match process_key {
            Some(k) => k,
            None => return,
        };

        let mut should_suspend = false;
        let mut reason = "";

        if let Some(mut state) = self.process_map.get_mut(&key) {
            state.category_flags |= category;
            
            // Count unique categories
            let unique_categories = state.category_flags.count_ones();

            println!(
                "[State machine] PID {} read sensitive file: {} (Categories touched: {})",
                key.pid, file_path, unique_categories
            );

            // 3. Evaluate Zero-Tolerance Vendor Ownership Rule
            let file_path_lower = file_path.to_lowercase();
            let image_path_lower = state.image_path.to_lowercase();
            
            let mut is_authorized_vendor = false;
            
            // Allow browsers to cross-read other browser profiles (e.g. for importing settings)
            let browsers = ["chrome", "firefox", "brave", "edge", "safari", "opera", "chromium", "vivaldi", "librewolf"];
            let is_image_browser = browsers.iter().any(|&b| image_path_lower.contains(b));
            let is_file_browser = browsers.iter().any(|&b| file_path_lower.contains(b));

            if is_image_browser && is_file_browser {
                is_authorized_vendor = true;
            } else {
                // For non-browsers, enforce strict 1:1 vendor ownership
                let vendors = [
                    "exodus", "discord", "telegram", 
                    "slack", "signal", "atomic", "ledger", 
                    "electrum", "keyring", "kwallet", "ssh"
                ];
                
                for vendor in vendors.iter() {
                    if file_path_lower.contains(vendor) && image_path_lower.contains(vendor) {
                        is_authorized_vendor = true;
                        break;
                    }
                }
            }

            if !is_authorized_vendor {
                should_suspend = true;
                reason = "Zero-Tolerance Ownership rule: Process is not authorized to read this credential category";
            }

            // Track distinct sensitive files read
            state.unique_files_read.insert(file_path.clone());
            let file_count = state.unique_files_read.len();
            
            // Sync to global velocity map
            self.path_velocity_map.insert(state.image_path.to_lowercase(), (state.unique_files_read.clone(), std::time::Instant::now()));

            if state.pending_network_connect {
                should_suspend = true;
                reason = "Reverse Path: Sensitive read attempt after outbound network connection";
            }
            
            // Heuristic C: Multi-Browser Directory Traversal
            if file_count > 2 {
                println!("[Heuristic C] PID {} traversed >2 unique sensitive credentials!", key.pid);
                should_suspend = true;
                reason = "Multi-Credential Directory Traversal Detected";
            }

            // Rule 1: Windows Ownership & Tamper verification
            #[cfg(windows)]
            {
                let accessor_lower = state.image_path.to_lowercase();
                let file_lower = file_path.to_lowercase();
                let is_browser_db = category == 0x01;
                let is_wallet = category == 0x04;
                
                let is_authorized_owner = if is_browser_db {
                    (file_lower.contains("google\\chrome") && accessor_lower.ends_with("chrome.exe"))
                    || (file_lower.contains("microsoft\\edge") && accessor_lower.ends_with("msedge.exe"))
                    || (file_lower.contains("brave") && accessor_lower.ends_with("brave.exe"))
                } else if is_wallet {
                    (file_lower.contains("exodus") && accessor_lower.contains("exodus.exe"))
                    || (file_lower.contains("electrum") && accessor_lower.contains("electrum.exe"))
                    || (file_lower.contains("atomic") && accessor_lower.contains("atomicwallet.exe"))
                } else {
                    false
                };

                let is_explorer = accessor_lower.ends_with("explorer.exe");
                
                if !is_authorized_owner && !is_explorer && !state.is_untrusted {
                    println!("[EDR ALERT] Windows Ownership rule breach! PID {} read sensitive file {}", key.pid, file_path);
                    should_suspend = true;
                    reason = "Unauthorized credential/wallet access attempt by non-owner process";
                }
            }
        }

        if should_suspend {
            let cat_str = match category {
                0x01 => "browser_db",
                0x04 => "wallet",
                0x08 => "app_data",
                0x10 => "ssh_keys",
                0x20 => "user_keystores",
                0x40 => "ai_agents",
                0x80 => "web_process",
                0x100 => "system_update",
                0x200 => "persistence_path",
                0x400 => "protected_binary",
                _ => "general",
            };
            self.suspend_process_tree(&key, reason, cat_str, &file_path);
        }
    }

    fn network_connect(&self, header: TelemetryHeader, _details: NetworkConnectDetails) {
        let mut process_key = None;
        for entry in self.process_map.iter() {
            if entry.key().pid == header.pid && !entry.value().terminated {
                process_key = Some(entry.key().clone());
                break;
            }
        }

        let key = match process_key {
            Some(k) => k,
            None => return,
        };

        let mut should_suspend = false;
        let mut reason = "";

        if let Some(mut state) = self.process_map.get_mut(&key) {
            state.pending_network_connect = true;
            
            // Evaluate Forward Path (Read -> Connect)
            if state.category_flags != 0 {
                should_suspend = true;
                reason = "Forward Path: Outbound network connection after reading sensitive credentials";
            }

            // Rule 2.D: Registry CDN Network Allowlist for Package Managers
            #[cfg(windows)]
            {
                let dest_ip = String::from_utf8_lossy(&_details.destination_ip)
                    .trim_end_matches('\0')
                    .to_string();
                let config_guard = self.config.read().unwrap();
                let domain_allowed = config_guard.is_domain_allowed(&dest_ip);
                let is_proxy_or_vpn = dest_ip.starts_with("127.") || dest_ip.starts_with("10.") || dest_ip.starts_with("192.168.") || dest_ip.starts_with("172.");
                if !domain_allowed && !is_proxy_or_vpn {
                    println!("[EDR ALERT] Package manager process tree connected to unauthorized C2/domain: {}!", dest_ip);
                    should_suspend = true;
                    reason = "Package manager install tree connected to unauthorized domain";
                }
            }
        }

        if should_suspend {
            let mut cat_str = "network";
            if let Some(state) = self.process_map.get(&key) {
                if (state.category_flags & 0x01) != 0 { cat_str = "browser_db"; }
                else if (state.category_flags & 0x02) != 0 { cat_str = "keyring"; }
                else if (state.category_flags & 0x04) != 0 { cat_str = "wallet"; }
                else if (state.category_flags & 0x08) != 0 { cat_str = "app_data"; }
                else if (state.category_flags & 0x10) != 0 { cat_str = "ssh_keys"; }
                else if (state.category_flags & 0x20) != 0 { cat_str = "user_keystores"; }
                else if (state.category_flags & 0x40) != 0 { cat_str = "ai_agents"; }
                else if (state.category_flags & 0x80) != 0 { cat_str = "web_process"; }
                else if (state.category_flags & 0x100) != 0 { cat_str = "system_update"; }
                else if (state.category_flags & 0x200) != 0 { cat_str = "persistence_path"; }
                else if (state.category_flags & 0x400) != 0 { cat_str = "protected_binary"; }
            }
            self.suspend_process_tree(&key, reason, cat_str, "");
        }
    }

    fn write_structured_alert(&self, pid: u32, severity: &str, category: &str, rule_path: &str, action: &str, message: &str) {
        let mut proc_info = crate::types::ProcessInfo {
            pid,
            ppid: 0,
            exe: String::new(),
            cmdline: String::new(),
            env: std::collections::HashMap::new(),
        };

        for entry in self.process_map.iter() {
            if entry.key().pid == pid {
                let state = entry.value();
                proc_info.ppid = state.ppid;
                proc_info.exe = state.image_path.clone();
                proc_info.cmdline = state.command_line.clone();
                proc_info.env = get_process_env_all(pid);
                break;
            }
        }

        let alert = crate::types::Alert {
            ts: Utc::now().to_rfc3339(),
            severity: severity.to_string(),
            category: category.to_string(),
            rule_path: rule_path.to_string(),
            process: proc_info,
            action: action.to_string(),
            message: message.to_string(),
        };

        let _ = self.alert_tx.send(alert.clone());

        if let Ok(json_str) = serde_json::to_string(&alert) {
            let _ = std::fs::create_dir_all("/var/log/kinnector");
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/var/log/kinnector/alerts.log")
            {
                use std::io::Write;
                let _ = writeln!(file, "{}", json_str);
            }
        }
    }

    // Recursively suspends the entire process tree using SIGSTOP and displays user prompts
    fn suspend_process_tree(&self, root_key: &ProcessKey, reason: &str, category: &str, rule_path: &str) {
        println!(
            "\n\x07\x07\x07[EDR ALERT] !!! STATE MACHINE THREAT DETECTED !!!"
        );
        println!("  - Target Root PID: {}", root_key.pid);
        println!("  - Reason: {}", reason);

        // Global terminal broadcast using wall for headless/SSH sessions
        let wall_msg = format!(
            "\x07\x07\x07\n!!! KINNECTOR EDR ALERT !!!\nSuspended PID {}. Reason: {}.\nRun 'antitheft-cli triage {}' to triage.\n",
            root_key.pid, reason, root_key.pid
        );
        let _ = std::process::Command::new("wall")
            .arg(&wall_msg)
            .output();

        // Spawn interactive Tmux popup if tmux is active
        let tmux_client_output = std::process::Command::new("tmux")
            .args(&["list-clients", "-F", "#{client_name}"])
            .output();
        if let Ok(out) = tmux_client_output {
            if out.status.success() {
                let clients_str = String::from_utf8_lossy(&out.stdout);
                for client in clients_str.lines() {
                    let client = client.trim();
                    if !client.is_empty() {
                        let popup_cmd = format!(
                            "tmux display-popup -c \"{}\" -E \"antitheft-cli triage {}\"",
                            client, root_key.pid
                        );
                        let _ = std::process::Command::new("sh")
                            .args(&["-c", &popup_cmd])
                            .output();
                    }
                }
            }
        }

        let mut pids_to_suspend = Vec::new();
        self.collect_descendants(root_key, &mut pids_to_suspend);
        pids_to_suspend.push(root_key.pid);

        for pid in pids_to_suspend.iter().copied() {
            if self.audit_mode {
                println!("  [AUDIT] Would suspend PID {}", pid);
            } else {
                println!("  [SIGSTOP] Suspending PID {}", pid);
                crate::os_utils::suspend_process(pid);
            }
        }
        
        let action = if self.audit_mode { "LOGGED" } else { "CONTAINED" };
        self.write_structured_alert(
            root_key.pid,
            "ALERT",
            category,
            rule_path,
            action,
            reason
        );

        println!("[EDR ALERT] Tree suspension completed.");

        // Spawn GUI/Desktop Notification alert prompt dynamically if a GUI session is active
        if !self.audit_mode {
            let mut has_gui = false;
            #[cfg(unix)]
            {
                let config_guard = self.config.read().unwrap();
                has_gui = get_active_session_context(&config_guard).is_some();
            }
            #[cfg(windows)]
            {
                extern "system" {
                    pub fn WTSGetActiveConsoleSessionId() -> u32;
                }
                has_gui = unsafe { WTSGetActiveConsoleSessionId() } != 0xFFFFFFFF;
            }

            if has_gui {
                let root_path = if let Some(state) = self.process_map.get(root_key) {
                    state.image_path.clone()
                } else {
                    "unknown".to_string()
                };

                let pid = root_key.pid;
                let reason_str = reason.to_string();
                let engine = self.process_map.clone();
                let parent_children = self.children_map.clone();
                let root_key_owned = root_key.clone();
                
                // Spawn blocking triage helper task on a dedicated OS thread so the
                // telemetry background thread is never stalled waiting for user input.
                // A 60-second timeout automatically sends DENY if the user ignores the prompt.
                let root_path_clone = root_path.clone();
                let reason_clone = reason_str.clone();
                tokio::spawn(async move {
                    let allowed = tokio::task::spawn_blocking(move || {
                        trigger_desktop_prompt(pid, &root_path_clone, &reason_clone)
                    })
                    .await
                    .unwrap_or(false);
                    
                    let mut pids_to_resolve = Vec::new();
                    collect_descendants_static(&root_key_owned, &parent_children, &mut pids_to_resolve);
                    pids_to_resolve.push(pid);

                    if allowed {
                        println!("[EDR RESPONSE] Administrator ALLOWED process tree. Resuming execution...");
                        
                        // Register root ancestor hash in trusted database and load inode to kernel map
                        #[cfg(unix)]
                        {
                            if let Ok(metadata) = std::fs::metadata(&root_path) {
                                use std::os::unix::fs::MetadataExt;
                                let inode = metadata.ino();
                                unsafe {
                                    crate::ffi::add_trusted_exec_inode(inode, 2); // Dynamic verification promotion
                                }
                                crate::trust_cache::add_to_user_allowlist(std::path::Path::new(&root_path));
                            }
                        }
                        #[cfg(windows)]
                        {
                            crate::trust_cache::add_to_user_allowlist(std::path::Path::new(&root_path));
                        }

                        for p in pids_to_resolve {
                            crate::os_utils::release_process(p);
                        }

                        // Clear flags
                        if let Some(mut state) = engine.get_mut(&root_key_owned) {
                            state.category_flags = 0;
                            state.pending_network_connect = false;
                        }
                    } else {
                        println!("[EDR RESPONSE] Administrator DENIED process tree. Terminating processes...");
                        for p in pids_to_resolve {
                            crate::os_utils::terminate_process(p);
                        }
                    }
                });
            } else {
                println!("[Agent] No active GUI session found. Leaving process tree suspended (manually triage via CLI).");
            }
        }
    }

    fn collect_descendants(&self, parent_key: &ProcessKey, pids: &mut Vec<u32>) {
        if let Some(children) = self.children_map.get(parent_key) {
            for child in children.iter() {
                pids.push(child.pid);
                self.collect_descendants(child, pids);
            }
        }
    }

    // Periodically run to evict terminated processes after their TTL has expired
    pub fn purge_expired_states(&self) {
        let now = Utc::now();
        self.process_map.retain(|_, state| {
            if let Some(deadline) = state.ttl_deadline {
                if now > deadline {
                    println!("[Purge] Evicting expired state for PID {}", state.key.pid);
                    return false;
                }
            }
            true
        });
    }

    // Recursively resumes the entire process tree using SIGCONT
    pub fn release_process_tree(&self, root_pid: u32) -> Result<(), String> {
        let mut target_key = None;
        for entry in self.process_map.iter() {
            if entry.key().pid == root_pid && !entry.value().terminated {
                target_key = Some(entry.key().clone());
                break;
            }
        }

        let key = match target_key {
            Some(k) => k,
            None => return Err(format!("Process PID {} not found or already terminated", root_pid)),
        };

        println!("\n[EDR COMMAND] !!! ADMINISTRATOR REQUESTED TREE RELEASE !!!");
        println!("  - Target Root PID: {}", key.pid);

        let mut pids_to_resume = Vec::new();
        self.collect_descendants(&key, &mut pids_to_resume);
        pids_to_resume.push(key.pid);

        for pid in pids_to_resume {
            println!("  [SIGCONT] Resuming PID {}", pid);
            crate::os_utils::release_process(pid);
        }

        // Reset the threat detection state for the process tree to allow normal execution
        if let Some(mut state) = self.process_map.get_mut(&key) {
            state.category_flags = 0;
            state.pending_network_connect = false;
        }

        self.write_structured_alert(
            key.pid,
            "INFO",
            "release",
            "",
            "RELEASED",
            "Containment released by administrator"
        );

        println!("[EDR COMMAND] Tree release completed.\n");
        Ok(())
    }

    // Recursively terminates the entire process tree using SIGKILL
    pub fn kill_process_tree(&self, root_pid: u32) -> Result<(), String> {
        let mut target_key = None;
        for entry in self.process_map.iter() {
            if entry.key().pid == root_pid && !entry.value().terminated {
                target_key = Some(entry.key().clone());
                break;
            }
        }

        let key = match target_key {
            Some(k) => k,
            None => return Err(format!("Process PID {} not found or already terminated", root_pid)),
        };

        println!("\n[EDR COMMAND] !!! ADMINISTRATOR REQUESTED TREE TERMINATION !!!");
        println!("  - Target Root PID: {}", key.pid);

        let mut pids_to_kill = Vec::new();
        self.collect_descendants(&key, &mut pids_to_kill);
        pids_to_kill.push(key.pid);

        for pid in pids_to_kill {
            println!("  [SIGKILL] Terminating PID {}", pid);
            crate::os_utils::terminate_process(pid);
        }

        self.write_structured_alert(
            key.pid,
            "INFO",
            "kill",
            "",
            "TERMINATED",
            "Process tree terminated by administrator"
        );

        println!("[EDR COMMAND] Tree termination completed.\n");
        Ok(())
    }

    fn terminate_threat_pkm(&self, key: &ProcessKey, reason: &str, category: &str, rule_path: &str) {
        println!("\n[SupplyChain] !!! SUPPLY CHAIN ATTACK INTERCEPTED !!!");
        println!("  - Target Root PID: {}", key.pid);
        println!("  - Reason: {}", reason);

        let mut pids_to_kill = Vec::new();
        self.collect_descendants(key, &mut pids_to_kill);
        pids_to_kill.push(key.pid);

        for pid in &pids_to_kill {
            println!("  [SIGKILL] Terminating PID {}", pid);
            if !self.audit_mode {
                crate::os_utils::terminate_process(*pid);
            }
        }

        for pid in &pids_to_kill {
            let mut k: Option<ProcessKey> = None;
            for entry in self.process_map.iter() {
                if entry.key().pid == *pid && !entry.value().terminated {
                    k = Some(entry.key().clone());
                    break;
                }
            }
            if let Some(pkey) = k {
                if let Some(mut state) = self.process_map.get_mut(&pkey) {
                    state.terminated = true;
                    state.ttl_deadline = Some(Utc::now() + Duration::minutes(5));
                }
            }
        }

        let event_pid = key.pid;
        self.write_structured_alert(
            event_pid,
            "CRITICAL",
            category,
            rule_path,
            "TERMINATED",
            reason
        );
    }

    fn file_open(&self, header: TelemetryHeader, details: crate::types::FileOpenDetails) {
        let file_path = String::from_utf8_lossy(&details.file_path)
            .trim_end_matches('\0')
            .to_string();

        let mut process_key = None;
        let event_pid = header.pid;
        for entry in self.process_map.iter() {
            if entry.key().pid == event_pid && !entry.value().terminated {
                process_key = Some(entry.key().clone());
                break;
            }
        }

        let key = match process_key {
            Some(k) => k,
            None => return,
        };

        let mut is_install = false;
        if let Some(state) = self.process_map.get(&key) {
            is_install = state.is_install_context;
        }

        if is_install {
            let path_lower = file_path.to_lowercase();
            if path_lower.contains("/var/run/docker.sock") || path_lower.contains("/run/containerd/containerd.sock") {
                self.terminate_threat_pkm(
                    &key,
                    &format!("Package install process attempted to access container runtime socket: {}", file_path),
                    "docker_socket_access",
                    &file_path
                );
                return;
            }

            let config_guard = self.config.read().unwrap();
            // Query category dynamically from sensitive files registry
            let mut is_cred = false;
            for (p_str, cat) in config_guard.sensitive_files() {
                if file_path.contains(&p_str) || p_str.contains(&file_path) {
                    // Category flags: BrowserDb=0x01, Wallet=0x04, SshKeys=0x10, UserKeystores=0x20
                    if (cat & 0x35) != 0 {
                        is_cred = true;
                        break;
                    }
                }
            }

            if !is_cred {
                // Check dynamic credential paths list
                let path_normalized = file_path.to_lowercase().replace('\\', "/");
                is_cred = config_guard.sensitive_credential_paths().iter().any(|p| {
                    let p_normalized = p.to_lowercase().replace('\\', "/");
                    path_normalized.contains(&p_normalized)
                });
            }

            if is_cred {
                #[cfg(unix)]
                {
                    self.terminate_threat_pkm(
                        &key,
                        &format!("Package install process attempted to read sensitive credentials: {}", file_path),
                        "credential_access",
                        &file_path
                    );
                }
                #[cfg(windows)]
                {
                    if let Some(state) = self.process_map.get(&key) {
                        let accessor_lower = state.image_path.to_lowercase();
                        let is_root_pkm = state.depth == 0;
                        let is_own_config = (path_lower.contains(".npmrc") && accessor_lower.contains("npm"))
                            || (path_lower.contains(".cargo\\credentials") && accessor_lower.contains("cargo"));

                        if !is_root_pkm || !is_own_config {
                            self.terminate_threat_pkm(
                                &key,
                                &format!("Package manager child script or unauthorized install process attempted to read credentials: {}", file_path),
                                "credential_access",
                                &file_path
                            );
                        }
                    }
                }
            }
        }
    }

    fn dup2(&self, header: TelemetryHeader, details: crate::types::Dup2Details) {
        let event_pid = header.pid;

        // Fix 1: The eBPF side never populates old_fd_type (it is always 0).
        // Instead, resolve the fd via the /proc/<pid>/fd/<oldfd> symlink.
        // A socket fd resolves to "socket:[<inode>]".
        // Copy packed field to local to avoid E0793 unaligned reference.
        let old_fd = details.old_fd;
        let new_fd = details.new_fd;
        let old_fd_is_socket_proc = std::fs::read_link(
            format!("/proc/{}/fd/{}", event_pid, old_fd)
        )
        .ok()
        .map(|p| p.to_string_lossy().starts_with("socket:"))
        .unwrap_or(false);

        // Fallback: if /proc lookup fails (e.g. race condition after fork),
        // treat a stdio-redirect as suspicious when the process already has a
        // pending outbound network connection.
        let old_fd_is_socket_fallback = !old_fd_is_socket_proc && {
            let mut has_pending = false;
            for entry in self.process_map.iter() {
                if entry.key().pid == event_pid && !entry.value().terminated {
                    has_pending = entry.value().pending_network_connect;
                    break;
                }
            }
            has_pending
        };

        let redirects_to_stdio = new_fd == 0 || new_fd == 1 || new_fd == 2;
        let is_reverse_shell = redirects_to_stdio && (old_fd_is_socket_proc || old_fd_is_socket_fallback);

        if is_reverse_shell {
            let mut process_key = None;
            for entry in self.process_map.iter() {
                if entry.key().pid == event_pid && !entry.value().terminated {
                    process_key = Some(entry.key().clone());
                    break;
                }
            }

            if let Some(key) = process_key {
                let mut should_terminate = false;
                let mut reason = "";
                let mut category = "";
                if let Some(state) = self.process_map.get(&key) {
                    if state.is_install_context {
                        should_terminate = true;
                        reason = "Package install process duplicated socket fd to stdin/stdout — classic reverse shell pattern. Terminated process tree.";
                        category = "reverse_shell";
                    }
                }

                if should_terminate {
                    self.terminate_threat_pkm(&key, reason, category, "");
                }
            }
        }
    }

    fn registry_write(&self, header: TelemetryHeader, details: RegistryWriteDetails) {
        let key_path = String::from_utf8_lossy(&details.key_path)
            .trim_end_matches('\0')
            .to_string();
        let value_name = String::from_utf8_lossy(&details.value_name)
            .trim_end_matches('\0')
            .to_string();

        let mut process_key = None;
        let event_pid = header.pid;
        for entry in self.process_map.iter() {
            if entry.key().pid == event_pid && !entry.value().terminated {
                process_key = Some(entry.key().clone());
                break;
            }
        }

        if let Some(key) = process_key {
            let mut is_install = false;
            if let Some(state) = self.process_map.get(&key) {
                is_install = state.is_install_context;
            }

            if is_install {
                let key_lower = key_path.to_lowercase();
                let is_persistence = key_lower.contains("microsoft\\windows\\currentversion\\run")
                    || key_lower.contains("system\\currentcontrolset\\services");

                if is_persistence {
                    self.terminate_threat_pkm(
                        &key,
                        &format!("Package install process attempted to write to persistence registry key: {}\\{}", key_path, value_name),
                        "persistence_path",
                        &key_path
                    );
                }
            }
        }
    }

    fn clipboard_write(&self, _header: TelemetryHeader, _details: ClipboardWriteDetails) {
        // Disabled for now
    }

    /// Fix 8/11: ptrace_attach heuristic.
    ///
    /// The eBPF side now emits EVT_PTRACE_ATTACH on *every* ptrace_access_check
    /// call, regardless of trust level. This handler correlates:
    ///   - Any process attaching to a high-value target (browser, ssh-agent,
    ///     gpg-agent) is flagged regardless of the tracer's trust level.
    ///   - An Untrusted process attaching to *any* target is flagged.
    fn ptrace_attach(&self, header: TelemetryHeader, details: crate::types::BpfPtraceAttachDetails) {
        let tracer_pid = header.pid;
        let tracee_pid = details.tracee_pid;

        // High-value targets: processes whose compromise is critical
        static HIGH_VALUE_TARGETS: &[&str] = &[
            "chrome", "firefox", "chromium", "brave", "opera",
            "ssh-agent", "gpg-agent", "gnome-keyring", "kwallet",
            "keepass", "1password", "bitwarden",
        ];

        // Resolve tracee executable name via /proc
        let tracee_exe = std::fs::read_link(format!("/proc/{}/exe", tracee_pid))
            .ok()
            .map(|p| p.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let tracee_is_high_value = HIGH_VALUE_TARGETS.iter()
            .any(|t| tracee_exe.contains(t));

        // Find tracer state in process map
        let mut tracer_is_untrusted = false;
        for entry in self.process_map.iter() {
            if entry.key().pid == tracer_pid && !entry.value().terminated {
                tracer_is_untrusted = entry.value().is_untrusted;
                break;
            }
        }

        if tracee_is_high_value || tracer_is_untrusted {
            let severity = if tracer_is_untrusted { "ALERT" } else { "WARN" };
            let reason = if tracee_is_high_value && tracer_is_untrusted {
                format!(
                    "Untrusted process PID {} is attaching via ptrace to high-value target '{}' (PID {})",
                    tracer_pid, tracee_exe, tracee_pid
                )
            } else if tracee_is_high_value {
                format!(
                    "PID {} is attaching via ptrace to high-value target '{}' (PID {}). \
                     Possible credential theft or browser injection.",
                    tracer_pid, tracee_exe, tracee_pid
                )
            } else {
                format!(
                    "Untrusted process PID {} is attaching via ptrace to PID {}",
                    tracer_pid, tracee_pid
                )
            };

            println!("[Heuristic PtraceAttach] {}", reason);
            self.write_structured_alert(
                tracer_pid,
                severity,
                "ptrace_injection",
                &tracee_exe,
                if self.audit_mode { "LOGGED" } else { "ALERTED" },
                &reason,
            );

            // If an untrusted process is actively ptrace-attaching, suspend it
            if tracer_is_untrusted && !self.audit_mode {
                for entry in self.process_map.iter() {
                    if entry.key().pid == tracer_pid && !entry.value().terminated {
                        let key = entry.key().clone();
                        drop(entry);
                        self.suspend_process_tree(
                            &key,
                            &reason,
                            "ptrace_injection",
                            "",
                        );
                        break;
                    }
                }
            }
        }
    }

    /// Fix 6: memory_protect heuristic.
    ///
    /// Called for both EVT_MEMORY_MAP (anonymous) and EVT_MEMORY_PROTECT
    /// (file-backed) events. The `is_file_backed` flag is set to true only for
    /// EVT_MEMORY_PROTECT, which means a loaded .so's executable pages are
    /// being re-protected — a strong module stomping signal.
    fn memory_protect(
        &self,
        header: TelemetryHeader,
        details: crate::types::MemoryMapBpfDetails,
        is_file_backed: bool,
    ) {
        let pid = header.pid;

        if !is_file_backed {
            // Anonymous PROT_EXEC change — existing behaviour, no new alert needed here
            // (the LSM hook already blocks this for Untrusted processes in Protect mode)
            return;
        }

        // File-backed PROT_EXEC change: potential module stomping
        // Alert if the process is tracked (regardless of trust level — even a
        // trusted process stomping its own .so segments is suspicious)
        let mut is_tracked = false;
        let mut process_key = None;
        for entry in self.process_map.iter() {
            if entry.key().pid == pid && !entry.value().terminated {
                is_tracked = true;
                process_key = Some(entry.key().clone());
                break;
            }
        }

        if !is_tracked {
            return;
        }

        // Copy packed fields to locals before using in format! (E0793)
        let inode = details.file_inode;
        let addr = details.addr;
        let reason = format!(
            "PID {} applied PROT_EXEC to a file-backed VMA (inode={}) at address 0x{:x}. \
             Possible module stomping / DLL hollowing.",
            pid, inode, addr
        );

        println!("[Heuristic ModuleStomping] {}", reason);

        self.write_structured_alert(
            pid,
            "ALERT",
            "module_stomping",
            "",
            if self.audit_mode { "LOGGED" } else { "ALERTED" },
            &reason,
        );

        // If the process is already Untrusted, escalate to suspension
        if let Some(key) = process_key {
            let is_untrusted = self.process_map.get(&key)
                .map(|s| s.is_untrusted)
                .unwrap_or(false);
            if is_untrusted && !self.audit_mode {
                self.suspend_process_tree(&key, &reason, "module_stomping", "");
            }
        }
    }

    /// Fix 10: image_load heuristic.
    ///
    /// Called when a file-backed executable mapping is created via lsm/mmap_file
    /// (i.e. when a .so / shared library is loaded). Alerts when:
    ///   - The loading process is Untrusted (unexpected module load)
    ///   - The loaded module's inode is NOT in the trust cache
    ///     (this catches side-loaded unsigned libraries in trusted processes)
    fn image_load(&self, header: TelemetryHeader, details: crate::types::BpfImageLoadDetails) {
        let pid = header.pid;
        let module_name = String::from_utf8_lossy(&details.module_path)
            .trim_end_matches('\0')
            .to_string();
        let file_inode = details.file_inode;

        // Only act on processes we are tracking
        let mut process_state_info: Option<(bool, bool)> = None; // (is_untrusted, is_install_context)
        for entry in self.process_map.iter() {
            if entry.key().pid == pid && !entry.value().terminated {
                process_state_info = Some((entry.value().is_untrusted, entry.value().is_install_context));
                break;
            }
        }

        let (is_untrusted, is_install_context) = match process_state_info {
            Some(info) => info,
            None => return,
        };

        // Check if this module's inode is in the trusted exec cache via FFI
        let is_trusted_module = unsafe {
            crate::ffi::is_trusted_exec_inode(file_inode)
        };

        // Alert conditions:
        //   1. Untrusted process loading ANY module (already suspicious by birth)
        //   2. Trusted process loading an untrusted module (side-loading)
        //   3. Install-context process loading unsigned module from temp path
        let should_alert = !is_trusted_module && (
            is_untrusted ||
            module_name.to_lowercase().contains("/tmp/") ||
            module_name.to_lowercase().contains("/dev/shm/")
        );

        if should_alert {
            let reason = format!(
                "PID {} loaded untrusted module '{}' (inode={}). {}",
                pid,
                module_name,
                file_inode,
                if is_untrusted { "Process is already Untrusted." }
                else if is_install_context { "Process is in install context." }
                else { "Possible SO side-loading." }
            );

            println!("[Heuristic ImageLoad] {}", reason);
            self.write_structured_alert(
                pid,
                "WARN",
                "so_sideload",
                &module_name,
                "LOGGED",
                &reason,
            );
        }
    }
}

// Static helper to collect descendants recursively in background task
fn collect_descendants_static(
    parent_key: &ProcessKey,
    children_map: &Arc<DashMap<ProcessKey, HashSet<ProcessKey>>>,
    pids: &mut Vec<u32>,
) {
    if let Some(children) = children_map.get(parent_key) {
        for child in children.iter() {
            pids.push(child.pid);
            collect_descendants_static(child, children_map, pids);
        }
    }
}

#[cfg(unix)]
fn get_process_env(pid: u32, var_name: &str) -> Option<String> {
    if let Ok(bytes) = std::fs::read(format!("/proc/{}/environ", pid)) {
        for slice in bytes.split(|&b| b == 0) {
            if let Ok(env_var) = std::str::from_utf8(slice) {
                if let Some(pos) = env_var.find('=') {
                    let name = &env_var[..pos];
                    let value = &env_var[pos + 1..];
                    if name == var_name {
                        return Some(value.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(windows)]
fn get_process_env(_pid: u32, _var_name: &str) -> Option<String> {
    None
}

#[cfg(unix)]
pub fn get_process_env_all(pid: u32) -> std::collections::HashMap<String, String> {
    let mut envs = std::collections::HashMap::new();
    if let Ok(bytes) = std::fs::read(format!("/proc/{}/environ", pid)) {
        for slice in bytes.split(|&b| b == 0) {
            if let Ok(env_var) = std::str::from_utf8(slice) {
                if let Some(pos) = env_var.find('=') {
                    let name = &env_var[..pos];
                    let value = &env_var[pos + 1..];
                    envs.insert(name.to_string(), value.to_string());
                }
            }
        }
    }
    envs
}

#[cfg(windows)]
pub fn get_process_env_all(_pid: u32) -> std::collections::HashMap<String, String> {
    std::collections::HashMap::new()
}

#[cfg(unix)]
struct SessionContext {
    uid: u32,
    username: String,
    display: Option<String>,
    wayland_display: Option<String>,
    dbus_addr: Option<String>,
}

#[cfg(unix)]
fn get_active_session_context(config: &kinnector_config::ConfigManager) -> Option<SessionContext> {
    let window_managers = config.window_managers();
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let pid_str = path.file_name().and_then(|f| f.to_str())?.to_owned();
        if !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let comm = std::fs::read_to_string(path.join("comm")).unwrap_or_default();
        if !window_managers.iter().any(|wm| comm.trim() == wm) {
            continue;
        }
        let wm_pid: u32 = pid_str.parse().ok()?;
        let uid = path.metadata().ok().map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.uid()
        })?;
        let username = get_username_from_uid(uid).unwrap_or_else(|| uid.to_string());
        let display = get_process_env(wm_pid, "DISPLAY");
        let wayland_display = get_process_env(wm_pid, "WAYLAND_DISPLAY");
        let dbus_addr = get_process_env(wm_pid, "DBUS_SESSION_BUS_ADDRESS")
            .or_else(|| Some(format!("unix:path=/run/user/{}/bus", uid)));
        return Some(SessionContext { uid, username, display, wayland_display, dbus_addr });
    }
    None
}

#[cfg(unix)]
fn get_username_from_uid(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            if let Ok(line_uid) = parts[2].parse::<u32>() {
                if line_uid == uid {
                    return Some(parts[0].to_string());
                }
            }
        }
    }
    None
}

#[cfg(unix)]
fn trigger_desktop_prompt(pid: u32, path: &str, reason: &str) -> bool {
    let config_guard = kinnector_config::ConfigManager::load_defaults();
    let ctx = match get_active_session_context(&config_guard) {
        Some(c) => c,
        None => return false,
    };

    let username = &ctx.username;
    let display_env = ctx.display.unwrap_or_else(|| ":0".to_string());
    let dbus_env = ctx.dbus_addr.unwrap_or_default();
    let title = "Kinnector EDR Alert";
    let text = format!(
        "Process '{}' (PID: {}) was suspended.\n\nReason: {}\n\nAllow or Terminate?",
        path, pid, reason
    );

    println!("[Agent GUI] Prompting user: sudo -u {} <dialog> ...", username);

    let tools = [
        ("zenity", vec!["--question", "--title", title, "--text", &text,
                        "--ok-label", "Allow", "--cancel-label", "Terminate"]),
        ("kdialog", vec!["--title", title, "--yesno", &text,
                         "--yes-label", "Allow", "--no-label", "Terminate"]),
        ("yad", vec!["--question", "--title", title, "--text", &text,
                     "--button", "Allow:0", "--button", "Terminate:1"]),
        ("xmessage", vec!["-center", "-buttons", "Allow:0,Terminate:1", &text]),
    ];

    for (tool, args) in &tools {
        if std::process::Command::new("which").arg(tool).output()
            .map(|o| o.status.success()).unwrap_or(false)
        {
            let mut cmd = std::process::Command::new("sudo");
            cmd.args(&["-u", username]);
            cmd.env("DISPLAY", &display_env);
            cmd.env("DBUS_SESSION_BUS_ADDRESS", &dbus_env);
            cmd.arg(tool);
            cmd.args(args);
            if let Ok(out) = cmd.output() {
                if out.status.success() {
                    println!("[Agent GUI] User allowed process PID {}", pid);
                    return true;
                } else {
                    println!("[Agent GUI] User denied or closed prompt for process PID {}", pid);
                    return false;
                }
            }
            break;
        }
    }

    println!("[Agent GUI] No supported dialog tool found. Leaving process suspended.");
    false
}

#[cfg(windows)]
fn trigger_desktop_prompt(pid: u32, path: &str, reason: &str) -> bool {
    use windows_sys::Win32::System::RemoteDesktop::WTS_CURRENT_SERVER_HANDLE;
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_YESNO, MB_ICONWARNING, IDYES};
    use std::ffi::CString;

    extern "system" {
        pub fn WTSGetActiveConsoleSessionId() -> u32;
        pub fn WTSSendMessageA(
            hserver: isize,
            sessionid: u32,
            ptitle: *mut u8,
            titlelength: u32,
            pmessage: *mut u8,
            messagelength: u32,
            style: u32,
            timeout: u32,
            presponse: *mut i32,
            wait: i32,
        ) -> i32;
    }

    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    if session_id == 0xFFFFFFFF {
        return false;
    }

    let title_c = CString::new("Kinnector EDR Alert").unwrap();
    let message_c = CString::new(format!(
        "Process '{}' (PID: {}) was suspended.\n\nReason: {}\n\nDo you want to ALLOW this process to continue?\n\n(Click 'No' or let it timeout to terminate)",
        path, pid, reason
    )).unwrap();

    let mut response: i32 = 0;
    unsafe {
        let result = WTSSendMessageA(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            title_c.as_ptr() as *mut u8,
            title_c.as_bytes().len() as u32,
            message_c.as_ptr() as *mut u8,
            message_c.as_bytes().len() as u32,
            MB_YESNO | MB_ICONWARNING,
            60,
            &mut response,
            1,
        );
        if result != 0 && response == IDYES {
            return true;
        }
    }
    false
}

fn is_profile_like_path(path: &str, config: &kinnector_config::ConfigManager) -> bool {
    let path_normalized = path.to_lowercase().replace('\\', "/");
    config.shell_profile_paths().iter().any(|p| {
        let p_normalized = p.to_lowercase().replace('\\', "/");
        if p_normalized.ends_with('/') {
            path_normalized.contains(&p_normalized)
        } else {
            path_normalized.ends_with(&p_normalized)
        }
    })
}

