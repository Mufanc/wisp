use crate::align::PtrAlign;
use crate::result::{WispError, WispResult};
use libc::{PT_LOAD, c_int, c_void, dl_phdr_info};
use region::Protection;
use std::ops::Range;
use std::{io, slice};

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

pub(crate) struct Elf {
    loads: Vec<Load>,
}

pub(crate) struct RxGaps {
    pub(crate) memory_ranges: Vec<Range<usize>>,
    pub(crate) target_ranges: Vec<Range<usize>>,
}

struct Load {
    range: Range<usize>,
    rx: bool,
}

struct Search {
    address: usize,
    found: Option<Elf>,
}

impl Elf {
    pub(crate) fn find_containing(address: usize) -> Option<Self> {
        let mut search = Search {
            address,
            found: None,
        };

        unsafe {
            libc::dl_iterate_phdr(
                Some(iterate_phdr_callback),
                (&mut search as *mut Search).cast(),
            )
        };

        search.found
    }

    pub(crate) fn rx_gaps(&self) -> WispResult<RxGaps> {
        let mut gaps = Vec::new();

        for tail in self.rx_tails() {
            let query_error = |source| WispError::MemoryIo {
                operation: "query ELF tail protection",
                address: tail.start,
                source: io::Error::other(source),
            };
            let mappings =
                region::query_range(tail.start as *const u8, tail.len()).map_err(query_error)?;

            for mapping in mappings {
                let mapping = mapping.map_err(query_error)?;

                if !mapping.protection().contains(Protection::READ_EXECUTE) {
                    continue;
                }

                let range = mapping.as_range();
                let start = tail.start.max(range.start);
                let end = tail.end.min(range.end);

                if end > start {
                    gaps.push(start..end);
                }
            }
        }

        Ok(RxGaps {
            memory_ranges: gaps,
            target_ranges: self.loads.iter().map(|load| load.range.clone()).collect(),
        })
    }

    fn rx_tails(&self) -> Vec<Range<usize>> {
        let mut tails = Vec::new();

        for (index, load) in self.loads.iter().enumerate() {
            if !load.rx || load.range.is_empty() {
                continue;
            }

            let start = load.range.end.next_multiple_of(4);
            let mut end = load.range.end.page_end();

            // The next LOAD's first page is not available as this segment's tail.
            if let Some(next) = self.loads.get(index + 1) {
                end = end.min(next.range.start.page_start());
            }

            if start < end {
                tails.push(start..end);
            }
        }

        tails
    }
}

unsafe extern "C" fn iterate_phdr_callback(
    info: *mut dl_phdr_info,
    _: usize,
    data: *mut c_void,
) -> c_int {
    let info = unsafe { &*info };
    let search = unsafe { &mut *data.cast::<Search>() };

    if info.dlpi_phnum == 0 || info.dlpi_phdr.is_null() {
        return 0;
    }

    let headers = unsafe { slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize) };
    let base = info.dlpi_addr as usize;
    let range = |header: &libc::Elf64_Phdr| {
        let start = base.checked_add(header.p_vaddr as usize)?;
        let end = start.checked_add(header.p_memsz as usize)?;
        Some(start..end)
    };

    if !headers.iter().any(|header| {
        header.p_type == PT_LOAD
            && range(header).is_some_and(|range| range.contains(&search.address))
    }) {
        return 0;
    }

    let mut loads: Vec<_> = headers
        .iter()
        .filter(|header| header.p_type == PT_LOAD)
        .filter_map(|header| {
            Some(Load {
                range: range(header)?,
                rx: header.p_flags & (PF_R | PF_W | PF_X) == PF_R | PF_X,
            })
        })
        .collect();

    loads.sort_by_key(|load| load.range.start);
    search.found = Some(Elf { loads });

    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_page_with_non_rx_load_has_no_tail() {
        let size = region::page::size();
        let elf = Elf {
            loads: vec![
                Load {
                    range: size..size + 20,
                    rx: true,
                },
                Load {
                    range: size + 32..size + 48,
                    rx: false,
                },
                Load {
                    range: size * 2..size * 3,
                    rx: false,
                },
            ],
        };
        assert!(elf.rx_tails().is_empty());
    }

    #[test]
    fn shared_rx_page_only_uses_last_load_tail() {
        let size = region::page::size();
        let elf = Elf {
            loads: vec![
                Load {
                    range: size..size + 20,
                    rx: true,
                },
                Load {
                    range: size + 32..size + 48,
                    rx: true,
                },
            ],
        };
        assert_eq!(elf.rx_tails(), vec![size + 48..size * 2]);
    }

    #[test]
    fn tail_does_not_include_whole_pages_between_loads() {
        let size = region::page::size();
        let elf = Elf {
            loads: vec![
                Load {
                    range: size..size + 20,
                    rx: true,
                },
                Load {
                    range: size * 4..size * 5,
                    rx: false,
                },
            ],
        };
        assert_eq!(elf.rx_tails(), vec![size + 20..size * 2]);
    }

    #[test]
    fn gaps_require_a_readable_executable_mapping() {
        use libc::{MAP_ANON, MAP_FAILED, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};

        let size = region::page::size();
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                PROT_READ,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, MAP_FAILED);
        let start = mapping as usize;
        let elf = Elf {
            loads: vec![Load {
                range: start..start + 20,
                rx: true,
            }],
        };
        let gaps = elf.rx_gaps().unwrap();
        assert!(gaps.memory_ranges.is_empty());
        assert_eq!(gaps.target_ranges, vec![start..start + 20]);
        unsafe { assert_eq!(libc::mprotect(mapping, size, PROT_READ | PROT_EXEC), 0) };
        let gaps = elf.rx_gaps().unwrap();
        assert_eq!(gaps.memory_ranges, vec![start + 20..start + size]);
        assert_eq!(gaps.target_ranges, vec![start..start + 20]);
        unsafe {
            assert_eq!(
                libc::mprotect(mapping, size, PROT_READ | PROT_WRITE | PROT_EXEC),
                0
            )
        };
        assert_eq!(
            elf.rx_gaps().unwrap().memory_ranges,
            vec![start + 20..start + size]
        );
        unsafe { assert_eq!(libc::munmap(mapping, size), 0) };
    }

    #[test]
    fn finds_own_elf_and_excludes_live_segments() {
        let target = finds_own_elf_and_excludes_live_segments as *const () as usize;
        let elf = Elf::find_containing(target).unwrap();
        let gaps = elf.rx_gaps().unwrap();
        assert!(
            gaps.target_ranges
                .iter()
                .any(|range| range.contains(&target))
        );
        for tail in gaps.memory_ranges {
            assert!(
                region::query(tail.start as *const u8)
                    .unwrap()
                    .protection()
                    .contains(Protection::READ_EXECUTE)
            );
            assert!(
                gaps.target_ranges
                    .iter()
                    .all(|range| tail.end <= range.start || range.end <= tail.start)
            );
        }
    }
}
