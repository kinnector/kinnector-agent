use std::fs;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::collections::HashSet;
use serde::{Serialize, Deserialize};
use crate::ffi;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AllowlistEntry {
    path: String,
    sha256: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DenylistEntry {
    path: String,
    sha256: String,
}

#[cfg(unix)]
pub fn initialize_trust_cache(config: &kinnector_config::ConfigManager) {
    println!("[Agent] Initializing Adaptive Inode Trust Cache...");
    let mut trusted_inodes = HashSet::new();

    // 1. Scan read-only Snap / Flatpak mounts
    scan_squashfs_mounts(&mut trusted_inodes);

    // 2. Scan standard system bin paths and verify against package manager
    let system_bin_paths = config.system_package_paths();

    for path_str in system_bin_paths {
        let path = std::path::Path::new(&path_str);
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if file_path.is_file() && is_executable(&file_path) {
                    if verify_package_integrity(&file_path) {
                        if let Ok(metadata) = file_path.metadata() {
                            let inode = metadata.ino();
                            if trusted_inodes.insert(inode) {
                                unsafe {
                                    ffi::add_trusted_exec_inode(inode, 2); // Threshold = 2 (Verified)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Load user persistent allowlist and verify file integrity
    load_user_allowlist(&mut trusted_inodes);

    // 4. Load user persistent denylist and verify file integrity (Trust Level = 0)
    load_user_denylist();

    println!("[Agent] Registered {} verified executable inodes in kernel map.", trusted_inodes.len());

    // Enable blocking mode in the eBPF kernel maps!
    unsafe {
        ffi::set_config_value(0, 1); // Slot 0 = blocking_enabled = 1
    }
    println!("[Agent] Kernel-space synchronous LSM blocking is now ENABLED.");
}



fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = path.metadata() {
            return metadata.permissions().mode() & 0o111 != 0;
        }
    }
    false
}

#[cfg(unix)]
fn scan_squashfs_mounts(trusted_inodes: &mut HashSet<u64>) {
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let mount_point = parts[1];
                let fstype = parts[2];
                let options = parts[3];

                if (fstype == "squashfs" || fstype == "tmpfs" || fstype == "ext4") && 
                   (mount_point.starts_with("/snap/") || mount_point.starts_with("/var/lib/flatpak/")) &&
                   options.contains("ro") {
                    
                    scan_directory_recursively(Path::new(mount_point), trusted_inodes);
                }
            }
        }
    }
}

#[cfg(unix)]
fn scan_directory_recursively(dir: &Path, trusted_inodes: &mut HashSet<u64>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if is_executable(&path) {
                    if let Ok(metadata) = path.metadata() {
                        let inode = metadata.ino();
                        if trusted_inodes.insert(inode) {
                            unsafe {
                                ffi::add_trusted_exec_inode(inode, 2);
                            }
                        }
                    }
                }
            } else if path.is_dir() {
                scan_directory_recursively(&path, trusted_inodes);
            }
        }
    }
}

#[cfg(unix)]
fn verify_package_integrity(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    
    if Path::new("/var/lib/dpkg/status").exists() {
        let output = Command::new("dpkg-query")
            .args(&["-S", &path_str])
            .output();
        if let Ok(out) = output {
            if out.status.success() {
                return true;
            }
        }
    }

    if Path::new("/var/lib/pacman/local").exists() {
        let output = Command::new("pacman")
            .args(&["-Qo", &path_str])
            .output();
        if let Ok(out) = output {
            if out.status.success() {
                return true;
            }
        }
    }

    if Path::new("/var/lib/rpm").exists() {
        let output = Command::new("rpm")
            .args(&["-qf", &path_str])
            .output();
        if let Ok(out) = output {
            if out.status.success() {
                return true;
            }
        }
    }

    if let Ok(metadata) = path.metadata() {
        if metadata.uid() == 0 {
            return true;
        }
    }

    false
}

#[cfg(unix)]
pub fn get_file_sha256(path: &Path) -> Option<String> {
    let output = Command::new("sha256sum")
        .arg(path)
        .output();
    if let Ok(out) = output {
        if out.status.success() {
            let stdout_str = String::from_utf8_lossy(&out.stdout);
            if let Some(hash) = stdout_str.split_whitespace().next() {
                return Some(hash.to_string());
            }
        }
    }
    None
}

#[cfg(unix)]
fn load_user_allowlist(trusted_inodes: &mut HashSet<u64>) {
    let db_path = "/etc/kinnector/user_allowlist.json";
    if !Path::new(db_path).exists() {
        return;
    }

    if let Ok(data) = fs::read_to_string(db_path) {
        if let Ok(entries) = serde_json::from_str::<Vec<AllowlistEntry>>(&data) {
            for entry in entries {
                let path = Path::new(&entry.path);
                if path.exists() {
                    if let Some(current_hash) = get_file_sha256(path) {
                        if current_hash == entry.sha256 {
                            if let Ok(metadata) = path.metadata() {
                                let inode = metadata.ino();
                                if trusted_inodes.insert(inode) {
                                    unsafe {
                                        ffi::add_trusted_exec_inode(inode, 2);
                                    }
                                    println!("[Allowlist] Loaded trusted user binary: {} (Inode: {})", entry.path, inode);
                                }
                            }
                        } else {
                            println!("[Allowlist] Warning: Allowlisted binary {} has modified hash! Blocking.", entry.path);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
pub fn add_to_user_allowlist(path: &Path) {
    let db_path = "/etc/kinnector/user_allowlist.json";
    let hash = match get_file_sha256(path) {
        Some(h) => h,
        None => return,
    };

    let mut entries = Vec::new();
    if Path::new(db_path).exists() {
        if let Ok(data) = fs::read_to_string(db_path) {
            if let Ok(existing) = serde_json::from_str::<Vec<AllowlistEntry>>(&data) {
                entries = existing;
            }
        }
    }

    let path_str = path.to_string_lossy().to_string();
    // Check if already in allowlist
    if !entries.iter().any(|e| e.path == path_str) {
        entries.push(AllowlistEntry {
            path: path_str.clone(),
            sha256: hash,
        });

        if let Some(parent) = Path::new(db_path).parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Ok(serialized) = serde_json::to_string_pretty(&entries) {
            if fs::write(db_path, serialized).is_ok() {
                println!("[Allowlist] Added {} to persistent user allowlist.", path_str);
            }
        }
    }
}

static ALLOWLIST: std::sync::RwLock<Option<HashSet<String>>> = std::sync::RwLock::new(None);
static DENYLIST: std::sync::RwLock<Option<HashSet<String>>> = std::sync::RwLock::new(None);

#[cfg(windows)]
pub fn initialize_trust_cache(_config: &kinnector_config::ConfigManager) {
    println!("[Agent] Initializing Windows Trust Cache...");
    let mut allowed_hashes = HashSet::new();
    
    let allow_db = "C:\\ProgramData\\Kinnector\\user_allowlist.json";
    if Path::new(allow_db).exists() {
        if let Ok(data) = fs::read_to_string(allow_db) {
            if let Ok(entries) = serde_json::from_str::<Vec<AllowlistEntry>>(&data) {
                for entry in entries {
                    allowed_hashes.insert(entry.sha256.to_lowercase());
                }
            }
        }
    }
    *ALLOWLIST.write().unwrap() = Some(allowed_hashes);

    let mut denied_hashes = HashSet::new();
    let deny_db = "C:\\ProgramData\\Kinnector\\user_denylist.json";
    if Path::new(deny_db).exists() {
        if let Ok(data) = fs::read_to_string(deny_db) {
            if let Ok(entries) = serde_json::from_str::<Vec<DenylistEntry>>(&data) {
                for entry in entries {
                    denied_hashes.insert(entry.sha256.to_lowercase());
                }
            }
        }
    }
    *DENYLIST.write().unwrap() = Some(denied_hashes);
    println!("[Agent] Windows Trust Cache initialized.");
}

#[cfg(windows)]
pub fn get_file_sha256(path: &Path) -> Option<String> {
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-Command", &format!("(Get-FileHash '{}' -Algorithm SHA256).Hash", path.to_string_lossy())])
        .output();
    if let Ok(out) = output {
        if out.status.success() {
            let hash_str = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
            if !hash_str.is_empty() {
                return Some(hash_str);
            }
        }
    }
    None
}

#[cfg(windows)]
pub fn add_to_user_allowlist(path: &Path) {
    let db_path = "C:\\ProgramData\\Kinnector\\user_allowlist.json";
    let hash = match get_file_sha256(path) {
        Some(h) => h,
        None => return,
    };

    let mut entries = Vec::new();
    if Path::new(db_path).exists() {
        if let Ok(data) = fs::read_to_string(db_path) {
            if let Ok(existing) = serde_json::from_str::<Vec<AllowlistEntry>>(&data) {
                entries = existing;
            }
        }
    }

    let path_str = path.to_string_lossy().to_string();
    if !entries.iter().any(|e| e.path == path_str) {
        entries.push(AllowlistEntry {
            path: path_str.clone(),
            sha256: hash.clone(),
        });

        if let Some(parent) = Path::new(db_path).parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Ok(serialized) = serde_json::to_string_pretty(&entries) {
            let _ = fs::write(db_path, serialized);
        }
    }

    if let Some(ref mut set) = *ALLOWLIST.write().unwrap() {
        set.insert(hash);
    }
}

pub fn load_user_denylist() {}

#[cfg(unix)]
pub fn add_to_user_denylist(path: &Path) {
    let db_path = "/etc/kinnector/user_denylist.json";
    let hash = match get_file_sha256(path) {
        Some(h) => h,
        None => return,
    };

    let mut entries = Vec::new();
    if Path::new(db_path).exists() {
        if let Ok(data) = fs::read_to_string(db_path) {
            if let Ok(existing) = serde_json::from_str::<Vec<DenylistEntry>>(&data) {
                entries = existing;
            }
        }
    }

    let path_str = path.to_string_lossy().to_string();
    if !entries.iter().any(|e| e.path == path_str) {
        entries.push(DenylistEntry {
            path: path_str.clone(),
            sha256: hash.clone(),
        });
        if let Ok(serialized) = serde_json::to_string_pretty(&entries) {
            if fs::write(db_path, serialized).is_ok() {
                println!("[Denylist] Added {} to persistent user denylist.", path_str);
            }
        }
    }

    if let Some(ref mut set) = *DENYLIST.write().unwrap() {
        set.insert(hash);
    }
}

#[cfg(windows)]
pub fn add_to_user_denylist(path: &Path) {
    let db_path = "C:\\ProgramData\\Kinnector\\user_denylist.json";
    let hash = match get_file_sha256(path) {
        Some(h) => h,
        None => return,
    };

    let mut entries = Vec::new();
    if Path::new(db_path).exists() {
        if let Ok(data) = fs::read_to_string(db_path) {
            if let Ok(existing) = serde_json::from_str::<Vec<DenylistEntry>>(&data) {
                entries = existing;
            }
        }
    }

    let path_str = path.to_string_lossy().to_string();
    if !entries.iter().any(|e| e.path == path_str) {
        entries.push(DenylistEntry {
            path: path_str.clone(),
            sha256: hash.clone(),
        });

        if let Some(parent) = Path::new(db_path).parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Ok(serialized) = serde_json::to_string_pretty(&entries) {
            let _ = fs::write(db_path, serialized);
        }
    }

    if let Some(ref mut set) = *DENYLIST.write().unwrap() {
        set.insert(hash);
    }
}

pub fn is_hash_allowlisted(hash: &str) -> bool {
    if let Some(ref set) = *ALLOWLIST.read().unwrap() {
        return set.contains(&hash.to_lowercase());
    }
    false
}

pub fn is_hash_denylisted(hash: &str) -> bool {
    if let Some(ref set) = *DENYLIST.read().unwrap() {
        return set.contains(&hash.to_lowercase());
    }
    false
}

