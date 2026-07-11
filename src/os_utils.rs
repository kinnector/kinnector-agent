#[cfg(unix)]
pub fn terminate_process(pid: u32) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
}

#[cfg(unix)]
pub fn suspend_process(pid: u32) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGSTOP);
    }
}

#[cfg(unix)]
pub fn release_process(pid: u32) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGCONT);
    }
}

#[cfg(windows)]
pub fn terminate_process(pid: u32) {
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    use windows_sys::Win32::Foundation::CloseHandle;
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle != 0 {
            TerminateProcess(handle, 1);
            CloseHandle(handle);
        }
    }
}

#[cfg(windows)]
pub fn suspend_process(pid: u32) {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};
    use windows_sys::Win32::Foundation::CloseHandle;

    extern "system" {
        pub fn GetModuleHandleA(lpModuleName: *const u8) -> isize;
        pub fn GetProcAddress(hModule: isize, lpProcName: *const u8) -> *const std::ffi::c_void;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
        if handle != 0 {
            let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
            if ntdll != 0 {
                let nt_suspend = GetProcAddress(ntdll, b"NtSuspendProcess\0".as_ptr());
                if !nt_suspend.is_null() {
                    let func: extern "system" fn(isize) -> i32 = std::mem::transmute(nt_suspend);
                    func(handle);
                }
            }
            CloseHandle(handle);
        }
    }
}

#[cfg(windows)]
pub fn release_process(pid: u32) {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};
    use windows_sys::Win32::Foundation::CloseHandle;

    extern "system" {
        pub fn GetModuleHandleA(lpModuleName: *const u8) -> isize;
        pub fn GetProcAddress(hModule: isize, lpProcName: *const u8) -> *const std::ffi::c_void;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
        if handle != 0 {
            let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
            if ntdll != 0 {
                let nt_resume = GetProcAddress(ntdll, b"NtResumeProcess\0".as_ptr());
                if !nt_resume.is_null() {
                    let func: extern "system" fn(isize) -> i32 = std::mem::transmute(nt_resume);
                    func(handle);
                }
            }
            CloseHandle(handle);
        }
    }
}

