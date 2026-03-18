use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;

use super::error::UnloaderError;
use super::memory::{alloc_remote_memory, remap_frozen_stub, snapshot_module_memory, write_remote_bytes};
use super::pe::{patch_entry_point, resolve_remote_export, restore_entry_point};
use super::process::{assert_process_is_x86, find_kernel32, find_module_info, find_process_id, is_module_loaded, open_process_full_access};
use super::shellcode::{build_freelibrary_shellcode, execute_remote_thread};

const MAX_FREE_LIBRARY_ATTEMPTS: u32 = 50;

pub struct UnloadConfig {
    pub process_name: String,
    pub dll_name: String,
    pub patch_dllmain: bool,
    pub freeze_stub: bool,
}

pub fn unload_dll(config: &UnloadConfig) -> Result<String, UnloaderError> {
    let mut log = String::new();

    log.push_str(&format!("[*] Searching for process '{}'\n", config.process_name));
    let process_id = find_process_id(&config.process_name)?;
    log.push_str(&format!("[+] PID: {}\n", process_id));

    let target_module = find_module_info(process_id, &config.dll_name)?;
    let target_base = target_module.base_address;
    let target_size = target_module.module_size;
    log.push_str(&format!(
        "[+] '{}' at {:#x} (size {:#x})\n",
        target_module.name, target_base, target_size
    ));

    let process_guard = open_process_full_access(process_id)?;
    let process = process_guard.0;

    assert_process_is_x86(process)?;
    log.push_str("[+] Architecture: x86 confirmed\n");

    let kernel32 = find_kernel32(process_id)?;
    let free_library_address = resolve_remote_export(process, kernel32.base_address, "FreeLibrary")?;
    log.push_str(&format!(
        "[+] kernel32 at {:#x}, FreeLibrary at {:#x}\n",
        kernel32.base_address, free_library_address
    ));

    let memory_snapshots = if config.freeze_stub {
        log.push_str("[*] Capturing module memory snapshot...\n");
        match snapshot_module_memory(process, target_base, target_size, &mut log) {
            Ok(snapshots) => Some(snapshots),
            Err(ref snapshot_error) => {
                log.push_str(&format!(
                    "[!] Snapshot failed: {} — continuing without stub\n",
                    snapshot_error
                ));
                None
            }
        }
    } else {
        None
    };

    let mut active_entry_patch = None;

    if config.patch_dllmain {
        log.push_str("[*] Patching DllMain entry point...\n");
        match patch_entry_point(process, target_base) {
            Ok(patch) => {
                log.push_str(&format!(
                    "[+] Entry point (RVA {:#x}) neutralized\n",
                    patch.entry_rva
                ));
                active_entry_patch = Some(patch);
            }
            Err(ref patch_error) => {
                log.push_str(&format!("[!] Patch failed: {}\n", patch_error));
            }
        }
    }

    let shellcode = build_freelibrary_shellcode(free_library_address as u32, target_base as u32);

    let remote_shellcode = alloc_remote_memory(process, shellcode.len(), PAGE_EXECUTE_READWRITE)?;
    write_remote_bytes(process, remote_shellcode.address as usize, &shellcode)?;
    log.push_str(&format!("[+] Shellcode at {:#x}\n", remote_shellcode.address as usize));

    log.push_str("[*] Executing FreeLibrary...\n");
    let mut unload_succeeded = false;

    'unload_loop: for attempt_number in 1..=MAX_FREE_LIBRARY_ATTEMPTS {
        if !is_module_loaded(process_id, &config.dll_name) {
            unload_succeeded = true;
            log.push_str(&format!(
                "[+] Module removed after {} call(s)\n",
                attempt_number - 1
            ));
            break;
        }

        match execute_remote_thread(process, remote_shellcode.address as usize, 0) {
            Ok(thread_exit_code) => {
                if thread_exit_code == 0 {
                    log.push_str(&format!(
                        "[!] FreeLibrary returned FALSE (attempt #{})\n",
                        attempt_number
                    ));

                    if attempt_number == 1 && active_entry_patch.is_none() {
                        log.push_str("[*] Auto-patching DllMain...\n");
                        if let Ok(patch) = patch_entry_point(process, target_base) {
                            active_entry_patch = Some(patch);
                            continue 'unload_loop;
                        }
                    }
                    break;
                }

                if attempt_number <= 3 || attempt_number % 10 == 0 {
                    log.push_str(&format!(
                        "[+] FreeLibrary returned TRUE (attempt #{})\n",
                        attempt_number
                    ));
                }
            }
            Err(ref thread_error) => {
                log.push_str(&format!("[!] Remote thread failed: {}\n", thread_error));
                break;
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    if !unload_succeeded {
        std::thread::sleep(std::time::Duration::from_millis(80));
        if !is_module_loaded(process_id, &config.dll_name) {
            unload_succeeded = true;
            log.push_str("[+] Module removal confirmed\n");
        }
    }

    if active_entry_patch.is_some() && is_module_loaded(process_id, &config.dll_name) {
        if let Some(ref patch) = active_entry_patch {
            let _ = restore_entry_point(process, target_base, patch);
            log.push_str("[*] Entry point restored\n");
        }
    }

    if unload_succeeded {
        if let Some(ref snapshots) = memory_snapshots {
            log.push_str("[*] Remapping frozen stub at original address...\n");
            std::thread::sleep(std::time::Duration::from_millis(50));

            if remap_frozen_stub(process, target_base, target_size, snapshots, &mut log) {
                log.push_str("[+] Stub active — existing hooks point to valid code\n");
            } else {
                log.push_str("[!] Remap failed — pending hooks may cause crash\n");
            }
        }

        log.push_str(&format!("[+] '{}' successfully unloaded\n", config.dll_name));
    } else {
        log.push_str(&format!("[-] Failed to unload '{}'\n", config.dll_name));
    }

    Ok(log)
}
