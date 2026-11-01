use dynasmrt::DynasmError;
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum WispError {
    #[error("patch range overlaps an existing hook")]
    Conflict,

    #[error("hook reservation is missing or installed instructions no longer match")]
    PatchMismatch,

    #[error("target address is null, unaligned, or its patch range overflows")]
    InvalidAddress,

    #[error("assembly error: {0}")]
    Dynasm(#[from] DynasmError),

    #[error("cannot finalize assembly while an executor is still alive")]
    AssemblerInUse,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("failed to {operation} at {address:#x}: {source}")]
    MemoryIo {
        operation: &'static str,
        address: usize,
        #[source]
        source: io::Error,
    },

    #[error("unsupported PC-relative instruction {instruction:#010x} at target offset {offset:#x}")]
    NotSupported { instruction: u32, offset: usize },
}

pub type WispResult<T> = Result<T, WispError>;
