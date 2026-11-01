use crate::align::PtrAlign;
use crate::errno::IoError;
use crate::result::{WispError, WispResult};
use libc::{PROT_EXEC, PROT_READ, PROT_WRITE};
use std::ffi::c_void;
use std::io;
use std::ptr;

pub(crate) unsafe fn write_memory(addr: *const c_void, data: &[u8]) -> WispResult<()> {
    unsafe {
        let mprotect_addr = addr.page_start();
        let mprotect_size = addr
            .byte_add(data.len())
            .page_end()
            .byte_offset_from_unsigned(mprotect_addr);

        let region = region::query(addr).map_err(|source| WispError::MemoryIo {
            operation: "query memory protection",
            address: addr as usize,
            source: io::Error::other(source),
        })?;

        libc::mprotect(
            mprotect_addr as _,
            mprotect_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
        )
        .io_err()
        .map_err(|source| WispError::MemoryIo {
            operation: "make memory writable (mprotect)",
            address: mprotect_addr as usize,
            source,
        })?;
        ptr::copy_nonoverlapping(data.as_ptr(), addr as _, data.len());
        libc::mprotect(
            mprotect_addr as _,
            mprotect_size,
            region.protection().bits() as _,
        )
        .io_err()
        .map_err(|source| WispError::MemoryIo {
            operation: "restore memory protection (mprotect)",
            address: mprotect_addr as usize,
            source,
        })?;
    }

    Ok(())
}
