use crate::align::PtrAlign;
use crate::asm::{self, BRANCH_RANGE};
use crate::errno::IoError;
use crate::result::{WispError, WispResult};
use libc::{MAP_ANON, MAP_FAILED, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
use region::page;
use std::ffi::c_void;
use std::io;
use std::ops::Range;
use std::ptr;

pub(crate) unsafe fn write_memory(address: *mut c_void, data: &[u8]) -> WispResult<()> {
    unsafe {
        let page_address = address.page_start();
        let page_len = address
            .byte_add(data.len())
            .page_end()
            .byte_offset_from_unsigned(page_address);

        let region = region::query(address).map_err(|source| WispError::MemoryIo {
            operation: "query memory protection",
            address: address as usize,
            source: io::Error::other(source),
        })?;

        libc::mprotect(page_address, page_len, PROT_READ | PROT_WRITE | PROT_EXEC)
            .io_err()
            .map_err(|source| WispError::MemoryIo {
                operation: "make memory writable (mprotect)",
                address: page_address as usize,
                source,
            })?;
        ptr::copy_nonoverlapping(data.as_ptr(), address.cast::<u8>(), data.len());
        libc::mprotect(page_address, page_len, region.protection().bits() as _)
            .io_err()
            .map_err(|source| WispError::MemoryIo {
                operation: "restore memory protection (mprotect)",
                address: page_address as usize,
                source,
            })?;
    }

    Ok(())
}

pub(crate) fn mmap_near(target: usize, align: usize) -> WispResult<Range<usize>> {
    let size = page::size();
    let lower = target.saturating_sub(BRANCH_RANGE).max(size).page_end();
    let upper = target.saturating_add(BRANCH_RANGE).page_start();
    let query_error = |source| WispError::MemoryIo {
        operation: "query nearby mappings",
        address: target,
        source: io::Error::other(source),
    };
    let regions = region::query_range(lower as *const u8, upper - lower)
        .map_err(query_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(query_error)?;
    let mut cursor = lower;

    // The sentinel also checks for a hole after the last mapping.
    for range in regions
        .iter()
        .map(|region| region.as_range())
        .chain(std::iter::once(upper..upper))
    {
        let candidate = cursor.checked_next_multiple_of(align.max(size));
        let candidate = candidate.filter(|&address| {
            address
                .checked_add(size)
                .is_some_and(|end| end <= range.start)
        });

        if let Some(candidate) = candidate {
            // A hint cannot replace an existing mapping, even if the snapshot is stale.
            let mapped = unsafe {
                libc::mmap(
                    candidate as _,
                    size,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANON,
                    -1,
                    0,
                )
            };

            if mapped == MAP_FAILED {
                return Err(WispError::MemoryIo {
                    operation: "allocate island page (mmap)",
                    address: candidate,
                    source: io::Error::last_os_error(),
                });
            }

            let address = mapped as usize;

            if address.is_multiple_of(align) && asm::branch_offset(target, address).is_ok() {
                return Ok(address..address + size);
            }

            unsafe { libc::munmap(mapped, size) };
        }

        cursor = cursor.max(range.end);

        if cursor >= upper {
            break;
        }
    }

    Err(WispError::Island)
}

pub(crate) fn make_rwx(memory: &Range<usize>) -> WispResult<()> {
    let address = memory.start.page_start();
    let len = memory.end.page_end() - address;

    // Protection changes cover the whole page, including live code preceding an ELF tail.
    unsafe { libc::mprotect(address as _, len, PROT_READ | PROT_WRITE | PROT_EXEC) }
        .io_err()
        .map_err(|source| WispError::MemoryIo {
            operation: "make island memory RWX (mprotect)",
            address,
            source,
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use region::Protection;
    use std::ptr;

    #[test]
    fn preparing_a_gap_keeps_its_page_writable_and_executable() {
        let size = page::size();
        let mapping = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_EXEC,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, MAP_FAILED);
        let address = mapping as usize;

        make_rwx(&(address + 4..address + 20)).unwrap();
        unsafe {
            let instruction = mapping.cast::<u32>().add(1);
            ptr::write(instruction, 0xd503201f);
            ptr::write(instruction, 0xd65f03c0);
            assert_eq!(ptr::read(instruction), 0xd65f03c0);
        }
        assert_eq!(
            region::query(mapping).unwrap().protection(),
            Protection::READ_WRITE_EXECUTE
        );
        unsafe { assert_eq!(libc::munmap(mapping, size), 0) };
    }
}
