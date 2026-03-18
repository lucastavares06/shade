use thiserror::Error;

#[derive(Debug, Error)]
pub enum UnloaderError {
    #[error("Process '{name}' not found")]
    ProcessNotFound { name: String },

    #[error("Failed to open process {pid}: error code {error_code}")]
    OpenProcessFailed { pid: u32, error_code: u32 },

    #[error("DLL '{dll_name}' not found in process {pid}")]
    DllNotFound { dll_name: String, pid: u32 },

    #[error("Failed to create snapshot: error code {error_code}")]
    SnapshotFailed { error_code: u32 },

    #[error("Failed to create remote thread: error code {error_code}")]
    RemoteThreadFailed { error_code: u32 },

    #[error("kernel32.dll not found in target process")]
    Kernel32NotFound,

    #[error("Function '{name}' not found in remote export table")]
    ExportNotFound { name: String },

    #[error("Failed to read memory: error code {error_code}")]
    ReadMemoryFailed { error_code: u32 },

    #[error("Failed to write memory: error code {error_code}")]
    WriteMemoryFailed { error_code: u32 },

    #[error("Failed to allocate memory: error code {error_code}")]
    AllocFailed { error_code: u32 },

    #[error("Failed to change memory protection: error code {error_code}")]
    VirtualProtectFailed { error_code: u32 },

    #[error("Invalid PE header")]
    InvalidPeHeader,

    #[error("Export table not found")]
    NoExportTable,

    #[error("Failed to snapshot module memory")]
    SnapshotMemoryFailed,
}
