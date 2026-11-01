use std::io;

#[derive(Debug, thiserror::Error)]
pub enum WispError {
    #[error("patch range overlaps an existing hook")]
    Conflict,

    #[error("hook reservation is missing or installed instructions no longer match")]
    PatchMismatch,

    #[error("target address is null, unaligned, or its patch range overflows")]
    InvalidAddress,

    #[error("failed to finalize assembly")]
    Dynasm,

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("backup region contains pc-relative instruction")]
    NotSupported,

    #[error("memory region error: {0}")]
    Region(#[from] region::Error),
}

pub type WispResult<T> = Result<T, WispError>;
