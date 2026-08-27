use crate::align::PtrAlign;
use crate::errno::IoError;
use crate::result::WispResult;
use libc::{PROT_EXEC, PROT_READ, PROT_WRITE};
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::ptr;

unsafe fn write_mem_ignore_perm(addr: *const c_void, data: &[u8]) -> WispResult<()> {
    let file = OpenOptions::new().write(true).open("/proc/self/mem")?;
    file.write_all_at(data, addr as _)?;

    Ok(())
}

unsafe fn write_mem_with_mprotect(addr: *const c_void, data: &[u8]) -> WispResult<()> {
    unsafe {
        let mprotect_addr = addr.page_start();
        let mprotect_size = addr
            .byte_add(data.len())
            .page_end()
            .byte_offset_from_unsigned(mprotect_addr);

        let region = region::query(addr)?;

        libc::mprotect(
            mprotect_addr as _,
            mprotect_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
        )
        .io_err()?;
        ptr::copy_nonoverlapping(data.as_ptr(), addr as _, data.len());
        libc::mprotect(
            mprotect_addr as _,
            mprotect_size,
            region.protection().bits() as _,
        )
        .io_err()?;
    }

    Ok(())
}

pub(crate) unsafe fn write_memory(addr: *const c_void, data: &[u8]) -> WispResult<()> {
    unsafe {
        if libc::geteuid() == 0 {
            write_mem_ignore_perm(addr, data)
        } else {
            write_mem_with_mprotect(addr, data)
        }
    }
}
