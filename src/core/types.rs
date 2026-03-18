use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Memory::{VirtualFreeEx, MEM_RELEASE};

pub struct SafeHandle(pub HANDLE);

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

pub struct RemoteAllocation {
    pub process_handle: HANDLE,
    pub address: *mut std::ffi::c_void,
}

impl Drop for RemoteAllocation {
    fn drop(&mut self) {
        if !self.address.is_null() {
            unsafe {
                let _ = VirtualFreeEx(self.process_handle, self.address, 0, MEM_RELEASE);
            }
        }
    }
}

#[derive(Clone)]
pub struct ModuleInfo {
    pub base_address: usize,
    pub module_size: u32,
    pub name: String,
}

pub struct MemoryRegionSnapshot {
    pub base_address: usize,
    pub data: Vec<u8>,
}

pub fn wide_slice_to_string(wide: &[u16]) -> String {
    let null_position = wide.iter().position(|&ch| ch == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..null_position])
}
