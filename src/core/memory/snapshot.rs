use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    MEM_FREE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

use crate::core::error::UnloaderError;
use crate::core::logger::{LogLevel, UnloadLogger};
use crate::core::types::MemoryRegionSnapshot;

use super::rw::write_remote_bytes;

pub fn snapshot_module_memory(
    process: HANDLE,
    module_base: usize,
    module_size: u32,
    logger: &mut dyn UnloadLogger,
) -> Result<Vec<MemoryRegionSnapshot>, UnloaderError> {
    let mut snapshots: Vec<MemoryRegionSnapshot> = Vec::new();
    let mut current_address = module_base;
    let module_end = module_base + module_size as usize;
    let mut total_bytes_captured: usize = 0;

    while current_address < module_end {
        let mut region_info = MEMORY_BASIC_INFORMATION::default();
        let query_result = unsafe {
            VirtualQueryEx(
                process,
                Some(current_address as *const std::ffi::c_void),
                &mut region_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if query_result == 0 {
            break;
        }

        let region_base = region_info.BaseAddress as usize;
        let region_size = region_info.RegionSize;
        let region_end = region_base + region_size;

        if region_info.State == MEM_COMMIT {
            let read_start = current_address.max(region_base);
            let read_end = module_end.min(region_end);
            let read_size = read_end.saturating_sub(read_start);

            if read_size > 0 {
                let mut region_data = vec![0u8; read_size];
                if super::rw::read_remote_bytes(process, read_start, &mut region_data).is_ok() {
                    total_bytes_captured += read_size;
                    snapshots.push(MemoryRegionSnapshot {
                        base_address: read_start,
                        protection: region_info.Protect,
                        data: region_data,
                    });
                }
            }
        }

        current_address = region_end;
    }

    logger.log(
        LogLevel::Success,
        &format!(
            "Snapshot: {} region(s), {} bytes captured",
            snapshots.len(),
            total_bytes_captured
        ),
    );

    if snapshots.is_empty() {
        return Err(UnloaderError::SnapshotMemoryFailed);
    }

    Ok(snapshots)
}

pub fn remap_frozen_stub(
    process: HANDLE,
    module_base: usize,
    module_size: u32,
    snapshots: &[MemoryRegionSnapshot],
    logger: &mut dyn UnloadLogger,
) -> bool {
    let bulk_allocation = unsafe {
        VirtualAllocEx(
            process,
            Some(module_base as *const std::ffi::c_void),
            module_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if !bulk_allocation.is_null() {
        logger.log(
            LogLevel::Success,
            &format!("Bulk allocation at {:#x}", bulk_allocation as usize),
        );

        let write_success = write_snapshots_to_allocation(
            process,
            snapshots,
            module_base,
            bulk_allocation as usize,
            logger,
        );

        if write_success {
            restore_region_protections(
                process,
                snapshots,
                module_base,
                bulk_allocation as usize,
                logger,
            );
        }

        return write_success;
    }

    logger.log(
        LogLevel::Warning,
        &format!(
            "Bulk alloc failed (code {}) — falling back to per-region",
            unsafe { GetLastError().0 }
        ),
    );

    per_region_remap(process, snapshots, logger)
}

fn per_region_remap(
    process: HANDLE,
    snapshots: &[MemoryRegionSnapshot],
    logger: &mut dyn UnloadLogger,
) -> bool {
    let mut regions_written: u32 = 0;
    let mut total_bytes_written: usize = 0;
    let mut regions_failed: u32 = 0;

    for snapshot in snapshots {
        let region_address = snapshot.base_address;
        let region_size = snapshot.data.len();

        if try_write_to_committed_region(process, region_address, region_size, &snapshot.data)
            || try_allocate_free_region(process, region_address, region_size, &snapshot.data)
            || try_fallback_commit(process, region_address, region_size, &snapshot.data)
        {
            restore_single_region_protection(
                process,
                region_address,
                region_size,
                snapshot.protection,
            );
            regions_written += 1;
            total_bytes_written += region_size;
        } else {
            logger.log(
                LogLevel::Warning,
                &format!(
                    "Region {:#x} ({} bytes) — all strategies failed",
                    region_address, region_size
                ),
            );
            regions_failed += 1;
        }
    }

    logger.log(
        LogLevel::Success,
        &format!(
            "Per-region: {} written ({} bytes), {} failed",
            regions_written, total_bytes_written, regions_failed
        ),
    );

    regions_written > 0
}

fn try_write_to_committed_region(
    process: HANDLE,
    address: usize,
    size: usize,
    data: &[u8],
) -> bool {
    let mut region_info = MEMORY_BASIC_INFORMATION::default();
    let query_result = unsafe {
        VirtualQueryEx(
            process,
            Some(address as *const std::ffi::c_void),
            &mut region_info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };

    if query_result == 0 || region_info.State != MEM_COMMIT {
        return false;
    }

    let mut old_protection = PAGE_PROTECTION_FLAGS(0);
    let protection_changed = unsafe {
        VirtualProtectEx(
            process,
            address as *const std::ffi::c_void,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        )
        .is_ok()
    };

    protection_changed && write_remote_bytes(process, address, data).is_ok()
}

fn try_allocate_free_region(process: HANDLE, address: usize, size: usize, data: &[u8]) -> bool {
    let mut region_info = MEMORY_BASIC_INFORMATION::default();
    let query_result = unsafe {
        VirtualQueryEx(
            process,
            Some(address as *const std::ffi::c_void),
            &mut region_info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };

    if query_result == 0 || region_info.State != MEM_FREE {
        return false;
    }

    const PAGE_SIZE: usize = 4096;
    let aligned_base = address & !(PAGE_SIZE - 1);
    let aligned_end = (address + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let aligned_size = aligned_end - aligned_base;

    let page_alloc = unsafe {
        VirtualAllocEx(
            process,
            Some(aligned_base as *const std::ffi::c_void),
            aligned_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    !page_alloc.is_null() && write_remote_bytes(process, address, data).is_ok()
}

fn try_fallback_commit(process: HANDLE, address: usize, size: usize, data: &[u8]) -> bool {
    let fallback_alloc = unsafe {
        VirtualAllocEx(
            process,
            Some(address as *const std::ffi::c_void),
            size,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )
    };

    !fallback_alloc.is_null() && write_remote_bytes(process, address, data).is_ok()
}

fn restore_region_protections(
    process: HANDLE,
    snapshots: &[MemoryRegionSnapshot],
    module_base: usize,
    allocation_base: usize,
    logger: &mut dyn UnloadLogger,
) {
    let mut restored_count: u32 = 0;

    for snapshot in snapshots {
        let target_address = snapshot.base_address - module_base + allocation_base;
        if restore_single_region_protection(
            process,
            target_address,
            snapshot.data.len(),
            snapshot.protection,
        ) {
            restored_count += 1;
        }
    }

    logger.log(
        LogLevel::Info,
        &format!("Restored protection on {} region(s)", restored_count),
    );
}

fn restore_single_region_protection(
    process: HANDLE,
    address: usize,
    size: usize,
    protection: PAGE_PROTECTION_FLAGS,
) -> bool {
    if protection.0 == 0 || protection == PAGE_EXECUTE_READWRITE {
        return true;
    }

    let mut old_protection = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            process,
            address as *const std::ffi::c_void,
            size,
            protection,
            &mut old_protection,
        )
        .is_ok()
    }
}

fn write_snapshots_to_allocation(
    process: HANDLE,
    snapshots: &[MemoryRegionSnapshot],
    module_base: usize,
    allocation_base: usize,
    logger: &mut dyn UnloadLogger,
) -> bool {
    let mut regions_written: u32 = 0;
    let mut total_bytes_written: usize = 0;

    for snapshot in snapshots {
        let target_address = snapshot.base_address - module_base + allocation_base;
        if write_remote_bytes(process, target_address, &snapshot.data).is_ok() {
            regions_written += 1;
            total_bytes_written += snapshot.data.len();
        }
    }

    logger.log(
        LogLevel::Success,
        &format!(
            "Stub: {} regions, {} bytes at {:#x}",
            regions_written, total_bytes_written, allocation_base
        ),
    );

    regions_written > 0
}
