use windows::Win32::Foundation::HANDLE;

use crate::core::error::UnloaderError;
use crate::core::memory::{read_remote_cstring, read_remote_u16, read_remote_u32};

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const PE_MAGIC_PE32: u16 = 0x10B;
const PE_MAGIC_PE32_PLUS: u16 = 0x20B;

pub fn resolve_remote_export(
    process: HANDLE,
    module_base: usize,
    function_name: &str,
) -> Result<usize, UnloaderError> {
    let dos_signature = read_remote_u16(process, module_base)?;
    if dos_signature != IMAGE_DOS_SIGNATURE {
        return Err(UnloaderError::InvalidPeHeader);
    }

    let pe_header_offset = read_remote_u32(process, module_base + 0x3C)? as usize;
    let nt_signature = read_remote_u32(process, module_base + pe_header_offset)?;
    if nt_signature != IMAGE_NT_SIGNATURE {
        return Err(UnloaderError::InvalidPeHeader);
    }

    let optional_header_base = module_base + pe_header_offset + 0x18;
    let pe_magic = read_remote_u16(process, optional_header_base)?;

    let export_dir_rva_offset = match pe_magic {
        PE_MAGIC_PE32 => optional_header_base + 0x60,
        PE_MAGIC_PE32_PLUS => optional_header_base + 0x70,
        _ => return Err(UnloaderError::InvalidPeHeader),
    };

    let export_dir_rva = read_remote_u32(process, export_dir_rva_offset)? as usize;
    if export_dir_rva == 0 {
        return Err(UnloaderError::NoExportTable);
    }

    let export_directory = module_base + export_dir_rva;
    let num_named_exports = read_remote_u32(process, export_directory + 0x18)? as usize;
    let address_table = module_base + read_remote_u32(process, export_directory + 0x1C)? as usize;
    let name_pointer_table = module_base + read_remote_u32(process, export_directory + 0x20)? as usize;
    let ordinal_table = module_base + read_remote_u32(process, export_directory + 0x24)? as usize;

    for name_index in 0..num_named_exports {
        let name_rva = read_remote_u32(process, name_pointer_table + name_index * 4)? as usize;
        let export_name = read_remote_cstring(process, module_base + name_rva, 128)?;

        if export_name == function_name {
            let ordinal = read_remote_u16(process, ordinal_table + name_index * 2)? as usize;
            let function_rva = read_remote_u32(process, address_table + ordinal * 4)? as usize;
            return Ok(module_base + function_rva);
        }
    }

    Err(UnloaderError::ExportNotFound { name: function_name.to_string() })
}
