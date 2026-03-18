use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
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
            UnloaderError::OpenProcessFailed {
                pid: process_id,
                error_code: GetLastError().0,
            }
        })?
    };

    Ok(SafeHandle(handle))
}

pub fn find_kernel32(process_id: u32) -> Result<ModuleInfo, UnloaderError> {
    find_module_info(process_id, "kernel32.dll")
        .map_err(|_| UnloaderError::Kernel32NotFound)
}
