use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    MEM_FREE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

use crate::core::error::UnloaderError;
use crate::core::types::MemoryRegionSnapshot;

use super::rw::write_remote_bytes;

pub fn snapshot_module_memory(
    process: HANDLE,
    module_base: usize,
    module_size: u32,
    log: &mut String,
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
                        data: region_data,
                    });
                }
            }
        }

        current_address = region_end;
    }

    log.push_str(&format!(
        "[+] Snapshot: {} region(s), {} bytes captured\n",
        snapshots.len(),
        total_bytes_captured
    ));

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
    log: &mut String,
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
        log.push_str(&format!(
            "[+] Bulk allocation at {:#x}\n",
            bulk_allocation as usize
        ));
        return write_snapshots_to_allocation(
            process,
            snapshots,
            module_base,
            bulk_allocation as usize,
            log,
        );
    }

    log.push_str(&format!(
        "[!] Bulk alloc failed (code {}) — falling back to per-region\n",
        unsafe { GetLastError().0 }
    ));

    let mut regions_written: u32 = 0;
    let mut total_bytes_written: usize = 0;
    let mut regions_failed: u32 = 0;

    for snapshot in snapshots {
        let region_address = snapshot.base_address;
        let region_size = snapshot.data.len();

        let mut region_info = MEMORY_BASIC_INFORMATION::default();
        let query_result = unsafe {
            VirtualQueryEx(
                process,
                Some(region_address as *const std::ffi::c_void),
                &mut region_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        let region_is_committed = query_result > 0 && region_info.State == MEM_COMMIT;
        let region_is_free = query_result > 0 && region_info.State == MEM_FREE;

        if region_is_committed {
            let mut old_protection = PAGE_PROTECTION_FLAGS(0);
            let protection_changed = unsafe {
                VirtualProtectEx(
                    process,
                    region_address as *const std::ffi::c_void,
                    region_size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protection,
                )
                .is_ok()
            };

            if protection_changed {
                if write_remote_bytes(process, region_address, &snapshot.data).is_ok() {
                    regions_written += 1;
                    total_bytes_written += region_size;
                    continue;
                }
            }
        }

        if region_is_free {
            const PAGE_SIZE: usize = 4096;
            let aligned_base = region_address & !(PAGE_SIZE - 1);
            let aligned_end = (region_address + region_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
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

            if !page_alloc.is_null() {
                if write_remote_bytes(process, region_address, &snapshot.data).is_ok() {
                    regions_written += 1;
                    total_bytes_written += region_size;
                    continue;
                }
            }
        }

        let fallback_alloc = unsafe {
            VirtualAllocEx(
                process,
                Some(region_address as *const std::ffi::c_void),
                region_size,
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if !fallback_alloc.is_null() {
            if write_remote_bytes(process, region_address, &snapshot.data).is_ok() {
                regions_written += 1;
                total_bytes_written += region_size;
                continue;
            }
        }

        log.push_str(&format!(
            "    [!] Region {:#x} ({} bytes) — all strategies failed\n",
            region_address, region_size
        ));
        regions_failed += 1;
    }

    log.push_str(&format!(
        "[+] Per-region: {} written ({} bytes), {} failed\n",
        regions_written, total_bytes_written, regions_failed
    ));

    regions_written > 0
}

fn write_snapshots_to_allocation(
    process: HANDLE,
    snapshots: &[MemoryRegionSnapshot],
    module_base: usize,
    allocation_base: usize,
    log: &mut String,
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

    log.push_str(&format!(
        "[+] Stub: {} regions, {} bytes at {:#x}\n",
        regions_written, total_bytes_written, allocation_base
    ));

    regions_written > 0
}
