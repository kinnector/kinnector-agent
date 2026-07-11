#[cfg(windows)]
pub mod windows_impl {
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::Write;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::DataExchange::{
    AddClipboardFormatListener, GetClipboardOwner, OpenClipboard, CloseClipboard, GetClipboardData
};
use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassExW,
    HWND_MESSAGE, MSG, WNDCLASSEXW, WM_CLIPBOARDUPDATE, GetWindowThreadProcessId
};

const CF_UNICODETEXT: u32 = 13;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;

fn encode_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

static mut PREV_CONTENT: String = String::new();
static mut PIPE_NAME: String = String::new();

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_CLIPBOARDUPDATE {
        // Handle clipboard update
        let mut writing_pid = 0;
        let owner_hwnd = GetClipboardOwner();
        if owner_hwnd != 0 {
            GetWindowThreadProcessId(owner_hwnd, &mut writing_pid);
        }

        let mut new_content = String::new();
        if OpenClipboard(hwnd) != 0 {
            let h_data = GetClipboardData(CF_UNICODETEXT);
            if h_data != 0 {
                let ptr = GlobalLock(h_data as *mut std::ffi::c_void) as *const u16;
                if !ptr.is_null() {
                    let mut len = 0;
                    while *ptr.add(len) != 0 {
                        len += 1;
                    }
                    let slice = std::slice::from_raw_parts(ptr, len);
                    new_content = String::from_utf16_lossy(slice);
                    GlobalUnlock(h_data as *mut std::ffi::c_void);
                }
            }
            CloseClipboard();
        }

        // Only process if content changed
        if new_content != PREV_CONTENT && !new_content.is_empty() {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;

            // Send to pipe
            if let Ok(mut pipe) = std::fs::OpenOptions::new()
                .write(true)
                .open(&PIPE_NAME)
            {
                let json = format!(
                    r#"{{"pid":{},"new_content":{:?},"prev_content":{:?},"timestamp":{}}}"#,
                    writing_pid, new_content, PREV_CONTENT, timestamp
                );
                let _ = writeln!(pipe, "{}", json);
            }

            PREV_CONTENT = new_content;
        }

        return 0;
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

pub fn main() {
    unsafe {
        let current_pid = std::process::id();
        let mut session_id = 0;
        ProcessIdToSessionId(current_pid, &mut session_id);

        PIPE_NAME = format!("\\\\.\\pipe\\kinnect-clipboard-{}", session_id);

        let class_name = encode_wide("KinnectorClipboardListenerClass");
        let wnd_class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: 0,
            hIcon: 0,
            hCursor: 0,
            hbrBackground: 0,
            lpszMenuName: null_mut(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: 0,
        };

        if RegisterClassExW(&wnd_class) == 0 {
            return;
        }

        let window_name = encode_wide("KinnectorClipboardListener");
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            window_name.as_ptr(),
            0,
            0, 0, 0, 0,
            HWND_MESSAGE,
            0,
            0,
            null_mut(),
        );

        if hwnd == 0 {
            return;
        }

        if AddClipboardFormatListener(hwnd) == 0 {
            return;
        }

        // Get initial content
        if OpenClipboard(hwnd) != 0 {
            let h_data = GetClipboardData(CF_UNICODETEXT);
            if h_data != 0 {
                let ptr = GlobalLock(h_data as *mut std::ffi::c_void) as *const u16;
                if !ptr.is_null() {
                    let mut len = 0;
                    while *ptr.add(len) != 0 {
                        len += 1;
                    }
                    let slice = std::slice::from_raw_parts(ptr, len);
                    PREV_CONTENT = String::from_utf16_lossy(slice);
                    GlobalUnlock(h_data as *mut std::ffi::c_void);
                }
            }
            CloseClipboard();
        }

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            DispatchMessageW(&msg);
        }
    }
}
} // mod windows_impl

#[cfg(windows)]
fn main() {
    windows_impl::main();
}

#[cfg(not(windows))]
fn main() {}
