use std::time::{Duration, Instant};

use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_FREE, PAGE_EXECUTE_READWRITE,
};

use super::error::UnloaderError;
use super::logger::{BufferLogger, LogLevel, UnloadLogger};
use super::memory::{
    alloc_remote_memory, remap_frozen_stub, snapshot_module_memory, write_remote_bytes,
};
use super::pe::{patch_entry_point, resolve_remote_export, EntryPointGuard};
use super::process::{
    assert_process_is_x86, find_kernel32, find_module_info, find_process_id, is_module_loaded,
    open_process_full_access,
};
use super::shellcode::{build_freelibrary_shellcode, execute_remote_thread};
use super::types::UnloadResult;

const DEFAULT_THREAD_TIMEOUT_MS: u32 = 5000;
const POST_UNLOAD_SETTLE_MS: u64 = 80;
const INTER_ATTEMPT_DELAY_MS: u64 = 10;
const PRE_REMAP_DELAY_MS: u64 = 50;

#[derive(Clone)]
pub enum RetryStrategy {
    Fixed {
        max_attempts: u32,
        delay: Duration,
    },
    #[allow(dead_code)]
    ExponentialBackoff {
        max_attempts: u32,
        base_delay: Duration,
        max_delay: Duration,
    },
    #[allow(dead_code)]
    UntilTimeout {
        deadline: Duration,
        delay: Duration,
    },
}

impl RetryStrategy {
    fn max_iterations(&self) -> u32 {
        match self {
            RetryStrategy::Fixed { max_attempts, .. } => *max_attempts,
            RetryStrategy::ExponentialBackoff { max_attempts, .. } => *max_attempts,
            RetryStrategy::UntilTimeout { .. } => u32::MAX,
        }
    }

    fn delay_for_attempt(&self, attempt: u32) -> Duration {
        match self {
            RetryStrategy::Fixed { delay, .. } => *delay,
            RetryStrategy::ExponentialBackoff {
                base_delay,
                max_delay,
                ..
            } => {
                let multiplier = 2u64.saturating_pow(attempt.saturating_sub(1));
                let computed = base_delay.saturating_mul(multiplier as u32);
                computed.min(*max_delay)
            }
            RetryStrategy::UntilTimeout { delay, .. } => *delay,
        }
    }

    fn is_expired(&self, elapsed: Duration) -> bool {
        match self {
            RetryStrategy::UntilTimeout { deadline, .. } => elapsed >= *deadline,
            _ => false,
        }
    }
}

impl Default for RetryStrategy {
    fn default() -> Self {
        RetryStrategy::Fixed {
            max_attempts: 50,
            delay: Duration::from_millis(INTER_ATTEMPT_DELAY_MS),
        }
    }
}

pub struct UnloadConfig {
    pub process_name: String,
    pub dll_name: String,
    pub patch_dllmain: bool,
    pub freeze_stub: bool,
    pub retry_strategy: RetryStrategy,
    pub thread_timeout_ms: u32,
}

impl UnloadConfig {
    pub fn new(process_name: String, dll_name: String) -> Self {
        Self {
            process_name,
            dll_name,
            patch_dllmain: true,
            freeze_stub: true,
            retry_strategy: RetryStrategy::default(),
            thread_timeout_ms: DEFAULT_THREAD_TIMEOUT_MS,
        }
    }
}

pub fn unload_dll(config: &UnloadConfig) -> Result<UnloadResult, UnloaderError> {
    let mut logger = BufferLogger::new();
    let result = execute_unload(config, &mut logger);

    match result {
        Ok(mut unload_result) => {
            unload_result.log = logger.into_output();
            Ok(unload_result)
        }
        Err(error) => {
            logger.log(LogLevel::Error, &error.to_string());
            Err(error)
        }
    }
}

fn execute_unload(
    config: &UnloadConfig,
    logger: &mut dyn UnloadLogger,
) -> Result<UnloadResult, UnloaderError> {
    let mut result = UnloadResult {
        module_unloaded: false,
        stub_remapped: false,
        entry_point_restored: false,
        freelibrary_calls: 0,
        log: String::new(),
    };

    logger.log(
        LogLevel::Info,
        &format!("Searching for process '{}'", config.process_name),
    );
    let process_id = find_process_id(&config.process_name)?;
    logger.log(LogLevel::Success, &format!("PID: {}", process_id));

    let target_module = find_module_info(process_id, &config.dll_name)?;
    let target_base = target_module.base_address;
    let target_size = target_module.module_size;
    logger.log(
        LogLevel::Success,
        &format!(
            "'{}' at {:#x} (size {:#x})",
            target_module.name, target_base, target_size
        ),
    );

    let process_guard = open_process_full_access(process_id)?;
    let process = process_guard.0;

    assert_process_is_x86(process)?;
    logger.log(LogLevel::Success, "Architecture: x86 confirmed");

    let kernel32 = find_kernel32(process_id)?;
    let free_library_address =
        resolve_remote_export(process, kernel32.base_address, "FreeLibrary")?;
    logger.log(
        LogLevel::Success,
        &format!(
            "kernel32 at {:#x}, FreeLibrary at {:#x}",
            kernel32.base_address, free_library_address
        ),
    );

    let memory_snapshots = if config.freeze_stub {
        logger.log(LogLevel::Info, "Capturing module memory snapshot...");
        match snapshot_module_memory(process, target_base, target_size, logger) {
            Ok(snapshots) => Some(snapshots),
            Err(ref snapshot_error) => {
                logger.log(
                    LogLevel::Warning,
                    &format!(
                        "Snapshot failed: {} — continuing without stub",
                        snapshot_error
                    ),
                );
                None
            }
        }
    } else {
        None
    };

    let mut entry_guard: Option<EntryPointGuard> = None;

    if config.patch_dllmain {
        logger.log(LogLevel::Info, "Patching DllMain entry point...");
        match patch_entry_point(process, target_base) {
            Ok(guard) => {
                logger.log(
                    LogLevel::Success,
                    &format!("Entry point (RVA {:#x}) neutralized", guard.entry_rva()),
                );
                entry_guard = Some(guard);
            }
            Err(ref patch_error) => {
                logger.log(LogLevel::Warning, &format!("Patch failed: {}", patch_error));
            }
        }
    }

    let shellcode = build_freelibrary_shellcode(free_library_address as u32, target_base as u32);
    let remote_shellcode = alloc_remote_memory(process, shellcode.len(), PAGE_EXECUTE_READWRITE)?;
    write_remote_bytes(process, remote_shellcode.address as usize, &shellcode)?;
    logger.log(
        LogLevel::Success,
        &format!("Shellcode at {:#x}", remote_shellcode.address as usize),
    );

    logger.log(LogLevel::Info, "Executing FreeLibrary...");

    let unload_start = Instant::now();
    let max_iterations = config.retry_strategy.max_iterations();

    for attempt_number in 1..=max_iterations {
        if config.retry_strategy.is_expired(unload_start.elapsed()) {
            logger.log(LogLevel::Warning, "Retry deadline exceeded");
            break;
        }

        if !is_module_loaded(process_id, &config.dll_name) {
            result.module_unloaded = true;
            logger.log(
                LogLevel::Success,
                &format!("Module removed after {} call(s)", result.freelibrary_calls),
            );
            break;
        }

        match execute_remote_thread(
            process,
            remote_shellcode.address as usize,
            0,
            config.thread_timeout_ms,
        ) {
            Ok(thread_exit_code) => {
                result.freelibrary_calls += 1;

                if thread_exit_code == 0 {
                    logger.log(
                        LogLevel::Warning,
                        &format!("FreeLibrary returned FALSE (attempt #{})", attempt_number),
                    );

                    if attempt_number == 1 && entry_guard.is_none() {
                        logger.log(LogLevel::Info, "Auto-patching DllMain...");
                        if let Ok(guard) = patch_entry_point(process, target_base) {
                            entry_guard = Some(guard);
                            continue;
                        }
                    }
                    break;
                }

                if attempt_number <= 3 || attempt_number % 10 == 0 {
                    logger.log(
                        LogLevel::Success,
                        &format!("FreeLibrary returned TRUE (attempt #{})", attempt_number),
                    );
                }
            }
            Err(UnloaderError::RemoteThreadTimeout { timeout_ms }) => {
                logger.log(
                    LogLevel::Error,
                    &format!("Remote thread timed out after {}ms", timeout_ms),
                );
                break;
            }
            Err(ref thread_error) => {
                logger.log(
                    LogLevel::Error,
                    &format!("Remote thread failed: {}", thread_error),
                );
                break;
            }
        }

        std::thread::sleep(config.retry_strategy.delay_for_attempt(attempt_number));
    }

    if !result.module_unloaded {
        std::thread::sleep(Duration::from_millis(POST_UNLOAD_SETTLE_MS));

        if !is_module_loaded(process_id, &config.dll_name) {
            result.module_unloaded = true;
            logger.log(LogLevel::Success, "Module removal confirmed");
        }
    }

    if !result.module_unloaded {
        if let Some(mut guard) = entry_guard {
            if is_module_loaded(process_id, &config.dll_name) {
                let _ = guard.restore_now();
                result.entry_point_restored = true;
                logger.log(LogLevel::Info, "Entry point restored");
            }
            guard.disarm();
        }

        logger.log(
            LogLevel::Error,
            &format!("Failed to unload '{}'", config.dll_name),
        );

        return Ok(result);
    }

    if let Some(guard) = entry_guard {
        guard.disarm();
    }

    if result.module_unloaded {
        result.stub_remapped = apply_frozen_stub(
            process,
            process_id,
            &config.dll_name,
            target_base,
            target_size,
            &memory_snapshots,
            logger,
        );
    }

    logger.log(
        LogLevel::Success,
        &format!("'{}' successfully unloaded", config.dll_name),
    );

    Ok(result)
}

fn apply_frozen_stub(
    process: windows::Win32::Foundation::HANDLE,
    process_id: u32,
    dll_name: &str,
    target_base: usize,
    target_size: u32,
    memory_snapshots: &Option<Vec<super::types::MemoryRegionSnapshot>>,
    logger: &mut dyn UnloadLogger,
) -> bool {
    let Some(ref snapshots) = memory_snapshots else {
        return false;
    };

    logger.log(LogLevel::Info, "Verifying address space is free...");
    if !verify_address_space_freed(process, target_base, target_size) {
        if is_module_loaded(process_id, dll_name) {
            logger.log(
                LogLevel::Warning,
                "Address space still occupied — skipping remap",
            );
            return false;
        }
    }

    logger.log(
        LogLevel::Info,
        "Remapping frozen stub at original address...",
    );
    std::thread::sleep(Duration::from_millis(PRE_REMAP_DELAY_MS));

    if remap_frozen_stub(process, target_base, target_size, snapshots, logger) {
        logger.log(
            LogLevel::Success,
            "Stub active — existing hooks point to valid code",
        );
        true
    } else {
        logger.log(
            LogLevel::Warning,
            "Remap failed — pending hooks may cause crash",
        );
        false
    }
}

fn verify_address_space_freed(
    process: windows::Win32::Foundation::HANDLE,
    module_base: usize,
    module_size: u32,
) -> bool {
    let mut region_info = MEMORY_BASIC_INFORMATION::default();
    let query_result = unsafe {
        VirtualQueryEx(
            process,
            Some(module_base as *const std::ffi::c_void),
            &mut region_info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };

    if query_result == 0 {
        return false;
    }

    region_info.State == MEM_FREE && region_info.RegionSize >= module_size as usize
}
