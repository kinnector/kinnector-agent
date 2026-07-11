use std::os::raw::c_char;

extern "C" {
    pub fn initialize_telemetry_engine(
        bpf_obj_path: *const c_char,
        socket_path: *const c_char,
        auth_token: *const c_char,
    ) -> bool;

    pub fn start_telemetry_engine() -> bool;

    pub fn stop_telemetry_engine();

    pub fn add_sensitive_inode(inode: u64, category: u32) -> bool;
    pub fn add_trusted_exec_inode(inode: u64, trust_level: u32) -> bool;
    /// Fix 10: query whether `inode` is present in the trusted_exec_inodes BPF map.
    /// Returns true if trusted, false if unknown/untrusted or BPF unavailable.
    pub fn is_trusted_exec_inode(inode: u64) -> bool;
    pub fn set_config_value(index: u32, value: u32) -> bool;
    pub fn update_process_threshold(pid: u32, start_time: u64, threshold: u32) -> bool;
    pub fn is_lsm_active() -> bool;
}
