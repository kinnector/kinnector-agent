use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use dashmap::DashMap;

pub struct YaraScanner {
    rules: Option<Arc<yara_x::Rules>>,
    scan_cache: Arc<DashMap<String, bool>>, // Maps SHA-256 to is_malicious
}

impl YaraScanner {
    pub fn new() -> Self {
        let mut compiler = yara_x::Compiler::new();
        let rules_dir = Path::new("/etc/kinnector/rules.d");
        let mut loaded_any = false;

        if rules_dir.exists() {
            if let Ok(entries) = fs::read_dir(rules_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("yar") {
                        if let Ok(src) = fs::read_to_string(&path) {
                            if let Err(e) = compiler.add_source(src.as_str()) {
                                eprintln!("[YARA-X] Failed to add rule file {}: {:?}", path.display(), e);
                            } else {
                                println!("[YARA-X] Loaded rule file: {}", path.display());
                                loaded_any = true;
                            }
                        }
                    }
                }
            }
        }

        let rules = if loaded_any {
            Some(Arc::new(compiler.build()))
        } else {
            println!("[YARA-X] No custom rules found in /etc/kinnector/rules.d/.");
            None
        };

        Self {
            rules,
            scan_cache: Arc::new(DashMap::new()),
        }
    }

    /// Scan a file path asynchronously using a blocking tokio task
    pub async fn scan_file(&self, path: PathBuf) -> bool {
        let rules_arc = match &self.rules {
            Some(r) => Arc::clone(r),
            None => return false, // No rules loaded, allow file
        };

        // File size cap: 32 MB
        if let Ok(metadata) = fs::metadata(&path) {
            if metadata.len() > 32 * 1024 * 1024 {
                println!("[YARA-X] Skipping scan for {}: file exceeds size cap of 32MB", path.display());
                return false;
            }
        }

        let hash = match crate::trust_cache::get_file_sha256(&path) {
            Some(h) => h,
            None => return false,
        };

        if let Some(cached) = self.scan_cache.get(&hash) {
            return *cached;
        }

        let cache_clone = self.scan_cache.clone();
        let scan_res = tokio::task::spawn_blocking(move || {
            let mut scanner = yara_x::Scanner::new(&rules_arc);
            scanner.set_timeout(std::time::Duration::from_secs(3));

            let data = match fs::read(&path) {
                Ok(d) => d,
                Err(_) => return false,
            };

            let scan_result = match scanner.scan(&data) {
                Ok(res) => res,
                Err(_) => return false,
            };
            let is_malicious = scan_result.matching_rules().len() > 0;
            
            if is_malicious {
                println!("[YARA-X ALERT] Threat matched on {}!", path.display());
                for rule in scan_result.matching_rules() {
                    println!("  - Rule matched: {}", rule.identifier());
                }
            }
            cache_clone.insert(hash, is_malicious);
            is_malicious
        })
        .await
        .unwrap_or(false);

        scan_res
    }
}
