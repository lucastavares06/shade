use std::path::Path;

use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};

use crate::core::error::UnloaderError;
use crate::core::types::{wide_slice_to_string, ModuleInfo, SafeHandle};

pub fn find_process_id(process_name: &str) -> Result<u32, UnloaderError> {
    let snapshot_handle = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|_| UnloaderError::SnapshotFailed { error_code: GetLastError().0 })?
    };
    let _snapshot_guard = SafeHandle(snapshot_handle);

    let target_lowercase = process_name.to_lowercase();
    let mut process_entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    if unsafe { Process32FirstW(snapshot_handle, &mut process_entry) }.is_err() {
        return Err(UnloaderError::ProcessNotFound { name: process_name.to_string() });
    }

    loop {
        if wide_slice_to_string(&process_entry.szExeFile).to_lowercase() == target_lowercase {
            return Ok(process_entry.th32ProcessID);
        }
        if unsafe { Process32NextW(snapshot_handle, &mut process_entry) }.is_err() {
            break;
        }
    }

    Err(UnloaderError::ProcessNotFound { name: process_name.to_string() })
}

pub fn find_module_info(process_id: u32, dll_name: &str) -> Result<ModuleInfo, UnloaderError> {
    let snapshot_handle = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id)
            .map_err(|_| UnloaderError::SnapshotFailed { error_code: GetLastError().0 })?
    };
    let _snapshot_guard = SafeHandle(snapshot_handle);

    let target_lowercase = Path::new(dll_name)
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .unwrap_or(dll_name)
        .to_lowercase();

    let mut module_entry = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    if unsafe { Module32FirstW(snapshot_handle, &mut module_entry) }.is_err() {
        return Err(UnloaderError::DllNotFound {
            dll_name: dll_name.to_string(),
            pid: process_id,
        });
    }

    loop {
        if wide_slice_to_string(&module_entry.szModule).to_lowercase() == target_lowercase {
            return Ok(ModuleInfo {
                base_address: module_entry.modBaseAddr as usize,
                module_size: module_entry.modBaseSize,
                name: wide_slice_to_string(&module_entry.szModule),
            });
        }
        if unsafe { Module32NextW(snapshot_handle, &mut module_entry) }.is_err() {
            break;
        }
    }

    Err(UnloaderError::DllNotFound {
        dll_name: dll_name.to_string(),
        pid: process_id,
    })
}

pub fn is_module_loaded(process_id: u32, dll_name: &str) -> bool {
    find_module_info(process_id, dll_name).is_ok()
}
