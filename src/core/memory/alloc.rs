use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_PROTECTION_FLAGS};

use crate::core::error::UnloaderError;
use crate::core::types::RemoteAllocation;

pub fn alloc_remote_memory(
    process: HANDLE,
    size: usize,
    protection: PAGE_PROTECTION_FLAGS,
) -> Result<RemoteAllocation, UnloaderError> {
    let address = unsafe {
        VirtualAllocEx(process, None, size, MEM_COMMIT | MEM_RESERVE, protection)
    };

    if address.is_null() {
        return Err(UnloaderError::AllocFailed {
            error_code: unsafe { GetLastError().0 },
        });
    }

    Ok(RemoteAllocation { process_handle: process, address })
}
