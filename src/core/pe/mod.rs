mod exports;
mod patch;

pub use exports::resolve_remote_export;
pub use patch::{patch_entry_point, restore_entry_point, EntryPointGuard};
