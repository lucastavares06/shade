mod alloc;
mod rw;
mod snapshot;

pub use alloc::alloc_remote_memory;
pub use rw::{read_remote_bytes, read_remote_cstring, read_remote_u16, read_remote_u32, write_remote_bytes};
pub use snapshot::{remap_frozen_stub, snapshot_module_memory};
