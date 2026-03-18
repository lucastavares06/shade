use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};

use crate::core::error::UnloaderError;

pub fn read_remote_bytes(
    process: HANDLE,
    address: usize,
    buffer: &mut [u8],
) -> Result<(), UnloaderError> {
    unsafe {
        ReadProcessMemory(
            process,
            address as *const std::ffi::c_void,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len(),
            None,
        )
        .map_err(|_| UnloaderError::ReadMemoryFailed { error_code: GetLastError().0 })
    }
}

pub fn read_remote_u16(process: HANDLE, address: usize) -> Result<u16, UnloaderError> {
    let mut buffer = [0u8; 2];
    read_remote_bytes(process, address, &mut buffer)?;
    Ok(u16::from_le_bytes(buffer))
}

pub fn read_remote_u32(process: HANDLE, address: usize) -> Result<u32, UnloaderError> {
    let mut buffer = [0u8; 4];
    read_remote_bytes(process, address, &mut buffer)?;
    Ok(u32::from_le_bytes(buffer))
}

pub fn write_remote_bytes(
    process: HANDLE,
    address: usize,
    data: &[u8],
) -> Result<(), UnloaderError> {
    unsafe {
        WriteProcessMemory(
            process,
            address as *const std::ffi::c_void,
            data.as_ptr() as *const std::ffi::c_void,
            data.len(),
            None,
        )
        .map_err(|_| UnloaderError::WriteMemoryFailed { error_code: GetLastError().0 })
    }
}

pub fn read_remote_cstring(
    process: HANDLE,
    address: usize,
    max_length: usize,
) -> Result<String, UnloaderError> {
    let mut buffer = vec![0u8; max_length];
    read_remote_bytes(process, address, &mut buffer)?;
    let null_position = buffer
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(buffer.len());
    Ok(String::from_utf8_lossy(&buffer[..null_position]).to_string())
}
