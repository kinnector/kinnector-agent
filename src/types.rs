#![allow(dead_code, non_camel_case_types)]
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    ProcessCreate = 1,
    ProcessStop = 2,
    FileRead = 3,
    FileCreate = 4,
    FileWrite = 5,
    FileRename = 6,
    NetworkConnect = 7,
    ImageLoad = 8,
    RegistryWrite = 9,
    ClipboardWrite = 10,
    CallStackFrame = 11,
    MemoryProtect = 12,
    PtraceAttach = 13,
    SSHAuth = 14,
    TerminalCommand = 15,
    FileOpen = 16,
    MemoryMap = 17,
    Dup2 = 18,
    Listen = 19,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TelemetrySource {
    ETW = 1,
    ESF = 2,
    OpenBSM = 3,
    eBPF = 4,
    fanotify = 5,
    BPF_LSM = 6,
    Log_FIM = 7,
    Clipboard = 8,
    CallStack = 9,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TelemetryHeader {
    pub sequence_number: u64,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub event_type: EventType,
    pub source: TelemetrySource,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessCreateDetails {
    pub child_pid: u32,
    pub real_parent_pid: u32,
    pub child_image_path: [u8; 512],
    pub child_command_line: [u8; 1024],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessStopDetails {
    pub exit_code: i32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileReadDetails {
    pub bytes_requested: u32,
    pub zone_id: i32,
    pub file_path: [u8; 512],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileCreateDetails {
    pub zone_id: i32,
    pub file_path: [u8; 512],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileWriteDetails {
    pub bytes_written: u32,
    pub file_path: [u8; 512],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileRenameDetails {
    pub source_path: [u8; 512],
    pub destination_path: [u8; 512],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NetworkConnectDetails {
    pub destination_ip: [u8; 46],
    pub destination_port: u16,
    pub protocol: [u8; 8],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageLoadDetails {
    pub is_signed: u8,
    pub module_path: [u8; 512],
    pub signer_subject: [u8; 256],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RegistryWriteDetails {
    pub key_path: [u8; 512],
    pub value_name: [u8; 256],
    pub value_data: [u8; 512],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ClipboardWriteDetails {
    pub owner_pid: u32,
    pub owner_is_foreground: u8,
    pub previous_content: [u8; 512],
    pub new_content: [u8; 512],
    pub content_type: [u8; 32],
    pub attribution: [u8; 16],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CallStackFrameDetails {
    pub frame_index: u32,
    pub return_address: u64,
    pub is_file_backed: u8,
    pub module_path: [u8; 512],
    pub notes: [u8; 128],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryProtectDetails {
    pub target_pid: u32,
    pub address: u64,
    pub length: u64,
    pub prot_flags: [u8; 64],
    pub old_prot_flags: [u8; 64],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PtraceAttachDetails {
    pub target_pid: u32,
    pub mode: [u8; 32],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SSHAuthDetails {
    pub username: [u8; 64],
    pub source_ip: [u8; 46],
    pub port: u16,
    pub auth_method: [u8; 32],
    pub status: [u8; 16],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TerminalCommandDetails {
    pub tty_device: [u8; 32],
    pub command: [u8; 512],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileOpenDetails {
    pub file_path: [u8; 512],
    pub flags: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Dup2Details {
    pub old_fd: i32,
    pub new_fd: i32,
    /// NOTE: This field is NEVER populated by the eBPF side (always 0).
    /// Use /proc/<pid>/fd/<old_fd> symlink resolution instead (Fix 1).
    pub old_fd_type: u8,
}

/// BPF-side MemoryMapDetails — matches the C struct in kinnector.bpf.c.
/// Used when decoding EVT_MEMORY_MAP and EVT_MEMORY_PROTECT events from eBPF.
/// The `file_inode` field is non-zero for file-backed VMAs (Fix 6 — module stomping).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryMapBpfDetails {
    pub addr: u64,
    pub length: u64,
    pub prot: u32,
    pub flags: u32,
    pub fd: i32,
    pub file_inode: u64,  // Fix 6: 0 for anonymous, non-zero for file-backed
}

/// BPF-side PtraceAttach details — compact layout matching kinnector.bpf.c.
/// Note: the C-side Rust `PtraceAttachDetails` uses [u8;32] for mode,
/// but the BPF struct uses u32. Use this struct when decoding from eBPF.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BpfPtraceAttachDetails {
    pub tracee_pid: u32,
    pub mode: u32,  // raw ptrace mode flags
}

/// BPF-side ImageLoad details — matches ImageLoadDetails in kinnector.bpf.c.
/// The `module_path` is the dentry (filename only, not full path).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BpfImageLoadDetails {
    pub file_inode: u64,
    pub module_path: [u8; 256],
}

// Struct matching full TelemetryEvent union size in C
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TelemetryEventRaw {
    pub header: TelemetryHeader,
    pub details_buffer: [u8; 1544], // Exactly matches C++ union size of 1544 bytes.
}
pub const RAW_EVENT_SIZE: usize = std::mem::size_of::<TelemetryEventRaw>();

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub cmdline: String,
    pub env: std::collections::HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Alert {
    pub ts: String,
    pub severity: String,
    pub category: String,
    pub rule_path: String,
    pub process: ProcessInfo,
    pub action: String,
    pub message: String,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TtyEventRaw {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub len: u32,
    pub is_write: u8,
    pub comm: [u8; 16],
    pub data: [u8; 1024],
}
pub const RAW_TTY_EVENT_SIZE: usize = std::mem::size_of::<TtyEventRaw>();

