use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};

use crate::core::error::UnloaderError;
use crate::core::memory::{read_remote_bytes, read_remote_u32, write_remote_bytes};

const DLLMAIN_RETURN_TRUE_STUB: [u8; 8] = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00];

pub struct EntryPointPatch {
    pub entry_rva: u32,
    pub original_bytes: Vec<u8>,
}

pub fn patch_entry_point(
    process: HANDLE,
    module_base: usize,
) -> Result<EntryPointPatch, UnloaderError> {
    let pe_header_offset = read_remote_u32(process, module_base + 0x3C)? as usize;
    let entry_rva = read_remote_u32(process, module_base + pe_header_offset + 0x28)?;

    if entry_rva == 0 {
        return Err(UnloaderError::InvalidPeHeader);
    }

    let entry_absolute = module_base + entry_rva as usize;
    let mut original_bytes = vec![0u8; 8];
    read_remote_bytes(process, entry_absolute, &mut original_bytes)?;

    let mut old_protection = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            process,
            entry_absolute as *const std::ffi::c_void,
            8,
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        )
        .map_err(|_| UnloaderError::VirtualProtectFailed {
            error_code: GetLastError().0,
        })?;
    }

    write_remote_bytes(process, entry_absolute, &DLLMAIN_RETURN_TRUE_STUB)?;

    Ok(EntryPointPatch { entry_rva, original_bytes })
}

pub fn restore_entry_point(
    process: HANDLE,
    module_base: usize,
    patch: &EntryPointPatch,
) -> Result<(), UnloaderError> {
    let entry_absolute = module_base + patch.entry_rva as usize;
    let mut old_protection = PAGE_PROTECTION_FLAGS(0);

    unsafe {
        let _ = VirtualProtectEx(
            process,
            entry_absolute as *const std::ffi::c_void,
            patch.original_bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        );
    }

    write_remote_bytes(process, entry_absolute, &patch.original_bytes)
}
