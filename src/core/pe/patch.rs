use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Memory::{
    VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

use crate::core::error::UnloaderError;
use crate::core::memory::{
    read_remote_bytes, read_remote_u16, read_remote_u32, write_remote_bytes,
};

const DLLMAIN_RETURN_TRUE_STUB: [u8; 8] = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00];
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;

pub struct EntryPointPatch {
    pub entry_rva: u32,
    pub original_bytes: Vec<u8>,
}

pub struct EntryPointGuard {
    process: HANDLE,
    module_base: usize,
    patch: EntryPointPatch,
    should_restore: bool,
}

impl EntryPointGuard {
    pub fn entry_rva(&self) -> u32 {
        self.patch.entry_rva
    }

    pub fn disarm(mut self) {
        self.should_restore = false;
    }

    pub fn restore_now(&mut self) -> Result<(), UnloaderError> {
        if self.should_restore {
            restore_entry_point(self.process, self.module_base, &self.patch)?;
            self.should_restore = false;
        }
        Ok(())
    }
}

impl Drop for EntryPointGuard {
    fn drop(&mut self) {
        if self.should_restore {
            let _ = restore_entry_point(self.process, self.module_base, &self.patch);
        }
    }
}

fn validate_pe_headers(process: HANDLE, module_base: usize) -> Result<(), UnloaderError> {
    let dos_signature = read_remote_u16(process, module_base)?;
    if dos_signature != IMAGE_DOS_SIGNATURE {
        return Err(UnloaderError::InvalidPeHeader {
            detail: format!("invalid DOS signature: {:#06x}", dos_signature),
        });
    }

    let pe_offset = read_remote_u32(process, module_base + 0x3C)? as usize;
    if pe_offset == 0 || pe_offset > 0x1000 {
        return Err(UnloaderError::InvalidPeHeader {
            detail: format!("PE offset out of range: {:#x}", pe_offset),
        });
    }

    let nt_signature = read_remote_u32(process, module_base + pe_offset)?;
    if nt_signature != IMAGE_NT_SIGNATURE {
        return Err(UnloaderError::InvalidPeHeader {
            detail: format!("invalid NT signature: {:#010x}", nt_signature),
        });
    }

    Ok(())
}

pub fn patch_entry_point(
    process: HANDLE,
    module_base: usize,
) -> Result<EntryPointGuard, UnloaderError> {
    validate_pe_headers(process, module_base)?;

    let pe_header_offset = read_remote_u32(process, module_base + 0x3C)? as usize;
    let entry_rva = read_remote_u32(process, module_base + pe_header_offset + 0x28)?;

    if entry_rva == 0 {
        return Err(UnloaderError::InvalidPeHeader {
            detail: "entry point RVA is zero".to_string(),
        });
    }

    let entry_absolute = module_base + entry_rva as usize;

    let mut original_bytes = vec![0u8; DLLMAIN_RETURN_TRUE_STUB.len()];
    read_remote_bytes(process, entry_absolute, &mut original_bytes)?;

    let mut old_protection = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            process,
            entry_absolute as *const std::ffi::c_void,
            DLLMAIN_RETURN_TRUE_STUB.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        )
        .map_err(|_| UnloaderError::VirtualProtectFailed {
            error_code: GetLastError().0,
        })?;
    }

    write_remote_bytes(process, entry_absolute, &DLLMAIN_RETURN_TRUE_STUB)?;

    Ok(EntryPointGuard {
        process,
        module_base,
        patch: EntryPointPatch {
            entry_rva,
            original_bytes,
        },
        should_restore: true,
    })
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
