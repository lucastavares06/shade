use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Threading::{
    IsWow64Process, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use crate::core::error::UnloaderError;
use crate::core::types::{ModuleInfo, SafeHandle};

use super::finder::find_module_info;

pub fn open_process_full_access(process_id: u32) -> Result<SafeHandle, UnloaderError> {
    let desired_access = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE;

    let handle = unsafe {
        OpenProcess(desired_access, false, process_id).map_err(|_| {
            let error_code = { GetLastError().0 };
            if error_code == 5 {
                return UnloaderError::AccessDenied;
            }
            UnloaderError::OpenProcessFailed {
                pid: process_id,
                error_code,
            }
        })?
    };

    Ok(SafeHandle(handle))
}

pub fn assert_process_is_x86(process: HANDLE) -> Result<(), UnloaderError> {
    let mut is_wow64: i32 = 0;
    unsafe { IsWow64Process(process, &mut is_wow64 as *mut i32 as *mut _) }
        .map_err(|_| UnloaderError::UnsupportedArchitecture)?;

    if is_wow64 == 0 {
        return Err(UnloaderError::UnsupportedArchitecture);
    }

    Ok(())
}

pub fn find_kernel32(process_id: u32) -> Result<ModuleInfo, UnloaderError> {
    find_module_info(process_id, "kernel32.dll")
        .map_err(|_| UnloaderError::Kernel32NotFound)
}
