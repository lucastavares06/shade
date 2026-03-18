use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, WaitForSingleObject, INFINITE,
};

use super::error::UnloaderError;

pub fn build_freelibrary_shellcode(free_library_address: u32, module_handle: u32) -> Vec<u8> {
    let mut shellcode: Vec<u8> = Vec::with_capacity(16);
    shellcode.push(0x68);
    shellcode.extend_from_slice(&module_handle.to_le_bytes());
    shellcode.push(0xB8);
    shellcode.extend_from_slice(&free_library_address.to_le_bytes());
    shellcode.push(0xFF);
    shellcode.push(0xD0);
    shellcode.push(0xC2);
    shellcode.push(0x04);
    shellcode.push(0x00);
    shellcode
}

pub fn execute_remote_thread(
    process: HANDLE,
    start_address: usize,
    parameter: usize,
) -> Result<u32, UnloaderError> {
    let thread_proc: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
        unsafe { std::mem::transmute(start_address) };

    let thread_handle = unsafe {
        CreateRemoteThread(
            process,
            None,
            0,
            Some(thread_proc),
            Some(parameter as *const std::ffi::c_void),
            0,
            None,
        )
        .map_err(|_| UnloaderError::RemoteThreadFailed {
            error_code: GetLastError().0,
        })?
    };

    unsafe { WaitForSingleObject(thread_handle, INFINITE) };

    let mut exit_code: u32 = 0;
    unsafe {
        let _ = GetExitCodeThread(thread_handle, &mut exit_code);
        let _ = CloseHandle(thread_handle);
    }

    Ok(exit_code)
}
