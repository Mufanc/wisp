use crate::align::PtrAlign;
use crate::asm::{self, BRANCH_RANGE, PATCH_LEN};
use crate::elf::Elf;
use crate::mman;
use crate::result::{WispError, WispResult};
use region::page;
use std::ops::Range;
use std::sync::Arc;

pub(crate) struct IslandAllocator {
    spaces: Vec<Space>,
}

pub(crate) struct Island {
    address: usize,
    len: usize,
}

struct Space {
    range: Range<usize>,
    scope: Scope,
    free: Vec<Range<usize>>,
}

// This is an allocation policy, unrelated to mmap's MAP_SHARED / MAP_PRIVATE flags.
#[derive(Clone)]
enum Scope {
    Shared,
    // Addresses of targets allowed to use this memory, not addresses of the memory itself.
    Private(Arc<[Range<usize>]>),
}

impl Scope {
    fn allows(&self, target: usize) -> bool {
        match self {
            Self::Shared => true,
            Self::Private(targets) => targets.iter().any(|range| range.contains(&target)),
        }
    }
}

impl Island {
    pub(crate) fn address(&self) -> usize {
        self.address
    }
}

impl IslandAllocator {
    pub(crate) const fn new() -> Self {
        Self { spaces: Vec::new() }
    }

    /// Allocates `size` bytes (a nonzero multiple of four) with byte alignment `align`.
    pub(crate) fn allocate_near(
        &mut self,
        target: usize,
        size: usize,
        align: usize,
    ) -> WispResult<Island> {
        if target == 0 || !target.is_multiple_of(PATCH_LEN) {
            return Err(WispError::InvalidAddress);
        }

        if !align.is_power_of_two() || align < PATCH_LEN {
            return Err(WispError::Island);
        }

        if size == 0 || !size.is_multiple_of(PATCH_LEN) || size > page::size() {
            return Err(WispError::Island);
        }

        self.register_gaps(target)?;

        if let Some(island) = self.try_allocate(target, size, align) {
            return Ok(island);
        }

        let memory = mman::mmap_near(target, align)?;

        if let Err(error) = self.add_spaces(std::slice::from_ref(&memory), Scope::Shared) {
            unsafe { libc::munmap(memory.start as _, memory.len()) };
            return Err(error);
        }

        self.try_allocate(target, size, align)
            .ok_or(WispError::Island)
    }

    // Allocation from registered memory does not query ELF metadata or create mappings.
    fn try_allocate(&mut self, target: usize, len: usize, align: usize) -> Option<Island> {
        self.spaces
            .iter_mut()
            .filter(|space| space.scope.allows(target))
            .find_map(|space| space.allocate(target, len, align))
    }

    fn add_spaces(&mut self, memories: &[Range<usize>], scope: Scope) -> WispResult<()> {
        let mut spaces = Vec::new();

        for memory in memories {
            let mut start = memory.start;

            // Each space stays within one page, so allocations never cross page boundaries.
            while start < memory.end {
                let end = memory.end.min(start.page_start() + page::size());

                spaces.push(Space::new(start..end, scope.clone())?);
                start = end;
            }
        }

        // Publish the batch only after every space has been initialized successfully.
        self.spaces.extend(spaces);
        self.spaces
            .sort_by_key(|space| matches!(space.scope, Scope::Shared));

        Ok(())
    }

    fn register_gaps(&mut self, target: usize) -> WispResult<()> {
        // Full private spaces still identify their ELF; rediscovery would register overlapping memory.
        if self
            .spaces
            .iter()
            .any(|space| matches!(space.scope, Scope::Private(_)) && space.scope.allows(target))
        {
            return Ok(());
        }

        let Some(elf) = Elf::find_containing(target) else {
            return Ok(());
        };
        let gaps = elf.rx_gaps()?;

        let scope = Scope::Private(gaps.target_ranges.into());

        self.add_spaces(&gaps.memory_ranges, scope)
    }

    pub(crate) fn release_module(&mut self, address: usize) -> WispResult<()> {
        let belongs_to_module =
            |space: &Space| matches!(space.scope, Scope::Private(_)) && space.scope.allows(address);

        if self
            .spaces
            .iter()
            .filter(|space| belongs_to_module(space))
            .any(|space| space.free.len() != 1 || space.free[0] != space.range)
        {
            return Err(WispError::ModuleInUse);
        }

        self.spaces.retain(|space| !belongs_to_module(space));

        Ok(())
    }

    /// The island must be unpublished or have no remaining executors or references.
    pub(crate) unsafe fn deallocate(&mut self, island: Island) {
        let space = self
            .spaces
            .iter_mut()
            .find(|space| space.range.contains(&island.address))
            .expect("unknown island allocation");

        space.free.push(island.address..island.address + island.len);
        space.free.sort_by_key(|range| range.start);

        let mut index = 0;

        while index + 1 < space.free.len() {
            if space.free[index].end == space.free[index + 1].start {
                space.free[index].end = space.free.remove(index + 1).end;
            } else {
                index += 1;
            }
        }
    }
}

impl Space {
    fn new(range: Range<usize>, scope: Scope) -> WispResult<Self> {
        mman::make_rwx(&range)?;

        Ok(Self {
            free: vec![range.clone()],
            range,
            scope,
        })
    }

    fn allocate(&mut self, target: usize, len: usize, align: usize) -> Option<Island> {
        let lower = target.saturating_sub(BRANCH_RANGE);

        for index in 0..self.free.len() {
            let range = self.free[index].clone();
            // An unreachable prefix does not rule out usable space later in this range.
            let address = range.start.max(lower).checked_next_multiple_of(align)?;
            let end = address.checked_add(len)?;

            if end > range.end || asm::branch_offset(target, address).is_err() {
                continue;
            }

            self.free.remove(index);

            if range.start < address {
                self.free.push(range.start..address);
            }

            if end < range.end {
                self.free.push(end..range.end);
            }

            self.free.sort_by_key(|range| range.start);

            return Some(Island { address, len });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::{MAP_ANON, MAP_FAILED, MAP_PRIVATE, PROT_EXEC, PROT_READ};
    use region::Protection;
    use std::ptr;

    struct Memory {
        address: usize,
        len: usize,
    }

    impl Memory {
        fn new() -> Self {
            let len = page::size() * 8;
            let mapping = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    len,
                    PROT_READ | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANON,
                    -1,
                    0,
                )
            };
            assert_ne!(mapping, MAP_FAILED);
            Self {
                address: mapping as usize,
                len,
            }
        }

        fn range(&self, start: usize, end: usize) -> Range<usize> {
            self.address + start..self.address + end
        }
    }

    impl Drop for Memory {
        fn drop(&mut self) {
            unsafe { assert_eq!(libc::munmap(self.address as _, self.len), 0) };
        }
    }

    #[test]
    fn releasing_a_module_requires_all_private_islands_to_be_free() {
        let memory = Memory::new();
        let size = page::size();
        let scope = Scope::Private(std::iter::once(memory.range(0, 128)).collect());
        let other_scope = Scope::Private(std::iter::once(memory.range(128, 256)).collect());
        let mut allocator = IslandAllocator::new();
        allocator
            .add_spaces(
                &[
                    memory.range(size, size + 16),
                    memory.range(2 * size, 2 * size + 16),
                ],
                scope.clone(),
            )
            .unwrap();
        allocator
            .add_spaces(&[memory.range(3 * size, 3 * size + 16)], other_scope)
            .unwrap();
        allocator
            .add_spaces(&[memory.range(4 * size, 5 * size)], Scope::Shared)
            .unwrap();
        let first = allocator.try_allocate(memory.address, 16, 4).unwrap();
        let second = allocator.try_allocate(memory.address, 16, 4).unwrap();
        unsafe { allocator.deallocate(first) };

        assert!(matches!(
            allocator.release_module(memory.address + 1),
            Err(WispError::ModuleInUse)
        ));
        assert_eq!(allocator.spaces.len(), 4);
        unsafe { allocator.deallocate(second) };
        allocator.release_module(memory.address + 1).unwrap();
        assert_eq!(allocator.spaces.len(), 2);
        assert!(
            allocator
                .spaces
                .iter()
                .all(|space| !matches!(space.scope, Scope::Private(_))
                    || space.scope.allows(memory.address + 128))
        );
        allocator.release_module(memory.address).unwrap();
        assert_eq!(allocator.spaces.len(), 2);
        assert_eq!(
            region::query((memory.address + size) as *const u8)
                .unwrap()
                .protection(),
            Protection::READ_WRITE_EXECUTE
        );
        allocator
            .add_spaces(&[memory.range(size, size + 16)], scope)
            .unwrap();
        assert_eq!(
            allocator
                .try_allocate(memory.address, 16, 4)
                .unwrap()
                .address(),
            memory.address + size
        );
    }

    #[test]
    fn releasing_a_module_does_not_require_its_memory_to_remain_mapped() {
        let memory = Memory::new();
        let address = memory.address;
        let scope = Scope::Private(std::iter::once(memory.range(0, 128)).collect());
        let mut allocator = IslandAllocator::new();
        allocator.add_spaces(&[memory.range(0, 16)], scope).unwrap();
        drop(memory);

        allocator.release_module(address + 1).unwrap();
        assert!(allocator.spaces.is_empty());
        allocator.release_module(address + 1).unwrap();
    }

    #[test]
    fn initializing_a_space_makes_its_page_rwx() {
        let memory = Memory::new();
        let address = memory.address as *const u8;
        assert_eq!(
            region::query(address).unwrap().protection(),
            Protection::READ_EXECUTE
        );
        let space = Space::new(memory.range(4, 20), Scope::Shared).unwrap();
        assert_eq!(
            region::query(address).unwrap().protection(),
            Protection::READ_WRITE_EXECUTE
        );
        assert_eq!(space.free, vec![memory.range(4, 20)]);
    }

    #[test]
    fn variable_allocations_coalesce_and_reuse_immediately() {
        let memory = Memory::new();
        let base = memory.address;
        let mut allocator = IslandAllocator::new();
        allocator
            .add_spaces(&[memory.range(0, page::size())], Scope::Shared)
            .unwrap();
        let a = allocator.allocate_near(base, 4, 4).unwrap();
        let b = allocator.allocate_near(base, 20, 4).unwrap();
        let c = allocator.allocate_near(base, 16, 4).unwrap();
        assert_eq!((a.address(), a.len), (base, 4));
        assert_eq!((b.address(), b.len), (base + 4, 20));
        assert_eq!((c.address(), c.len), (base + 24, 16));
        unsafe {
            allocator.deallocate(b);
            allocator.deallocate(a);
        }
        let joined = allocator.allocate_near(base, 24, 4).unwrap();
        assert_eq!((joined.address(), joined.len), (base, 24));
        unsafe {
            allocator.deallocate(c);
            allocator.deallocate(joined);
        }
        assert_eq!(
            allocator.spaces[0].free,
            vec![memory.range(0, page::size())]
        );
    }

    #[test]
    fn private_space_precedes_existing_shared_space_and_is_reused() {
        let memory = Memory::new();
        let base = memory.address;
        let scope = Scope::Private(std::iter::once(memory.range(0, 0x100)).collect());
        let mut allocator = IslandAllocator::new();
        allocator
            .add_spaces(&[memory.range(0x4000, 0x4100)], Scope::Shared)
            .unwrap();
        allocator
            .add_spaces(&[memory.range(0x2000, 0x2010)], scope)
            .unwrap();

        let private = allocator.allocate_near(base, 16, 4).unwrap();
        let shared = allocator.allocate_near(base, 4, 4).unwrap();
        assert_eq!(private.address(), base + 0x2000);
        assert_eq!(shared.address(), base + 0x4000);
        unsafe { allocator.deallocate(private) };
        assert_eq!(
            allocator.allocate_near(base, 16, 4).unwrap().address(),
            base + 0x2000
        );
    }

    #[test]
    fn fragmented_private_space_falls_back_without_moving_live_allocations() {
        let memory = Memory::new();
        let base = memory.address;
        let scope = Scope::Private(std::iter::once(memory.range(0, 0x100)).collect());
        let mut allocator = IslandAllocator::new();
        allocator
            .add_spaces(&[memory.range(0x2000, 0x2014)], scope)
            .unwrap();
        allocator
            .add_spaces(&[memory.range(0x4000, 0x4100)], Scope::Shared)
            .unwrap();

        let first = allocator.allocate_near(base, 8, 4).unwrap();
        let middle = allocator.allocate_near(base, 4, 4).unwrap();
        let last = allocator.allocate_near(base, 8, 4).unwrap();
        unsafe {
            allocator.deallocate(first);
            allocator.deallocate(last);
        }
        assert_eq!(
            allocator.allocate_near(base, 16, 4).unwrap().address(),
            base + 0x4000
        );
        assert_eq!(middle.address(), base + 0x2008);
        assert_eq!(
            allocator.spaces[0].free,
            vec![memory.range(0x2000, 0x2008), memory.range(0x200c, 0x2014)]
        );
    }

    #[test]
    fn skips_unreachable_prefix_without_losing_it() {
        let memory = Memory::new();
        let base = memory.address;
        let mut space = Space::new(memory.range(0, 0x100), Scope::Shared).unwrap();
        let island = space.allocate(base + BRANCH_RANGE + 4, 20, 4).unwrap();
        assert_eq!(island.address(), base + 4);
        assert_eq!(
            space.free,
            vec![memory.range(0, 4), memory.range(24, 0x100)]
        );
        assert_eq!(space.allocate(base, 4, 4).unwrap().address(), base);
    }

    #[test]
    fn gaps_are_private_to_their_target_ranges_and_pages_are_shared() {
        let memory = Memory::new();
        let base = memory.address;
        let scope =
            Scope::Private(vec![memory.range(0x1000, 0x1100), memory.range(0x3000, 0x3100)].into());
        let mut allocator = IslandAllocator::new();
        allocator
            .add_spaces(
                &[memory.range(0x2000, 0x2100), memory.range(0x2200, 0x2300)],
                scope,
            )
            .unwrap();
        allocator
            .add_spaces(&[memory.range(0x4000, 0x4100)], Scope::Shared)
            .unwrap();

        match (&allocator.spaces[0].scope, &allocator.spaces[1].scope) {
            (Scope::Private(a), Scope::Private(b)) => assert!(Arc::ptr_eq(a, b)),
            _ => panic!("expected private spaces"),
        }
        assert_eq!(
            allocator
                .try_allocate(base + 0x1000, 4, 4)
                .unwrap()
                .address(),
            base + 0x2000
        );
        assert_eq!(
            allocator
                .try_allocate(base + 0x3000, 4, 4)
                .unwrap()
                .address(),
            base + 0x2004
        );
        // Being between two LOAD segments does not grant access to this ELF's gap space.
        assert_eq!(
            allocator
                .try_allocate(base + 0x2000, 4, 4)
                .unwrap()
                .address(),
            base + 0x4000
        );
    }

    #[test]
    fn allocations_stay_in_one_page_and_reject_invalid_sizes() {
        let memory = Memory::new();
        let size = page::size();
        let target = memory.address + size;
        let mut allocator = IslandAllocator::new();
        allocator
            .add_spaces(&[memory.range(size - 16, size)], Scope::Shared)
            .unwrap();
        assert!(allocator.try_allocate(target, 20, 4).is_none());
        assert_eq!(
            allocator.allocate_near(target, 16, 4).unwrap().address(),
            target - 16
        );
        for invalid_size in [0, 1, 2, 3, 5, usize::MAX, usize::MAX - 3, size + PATCH_LEN] {
            assert!(matches!(
                allocator.allocate_near(target, invalid_size, 4),
                Err(WispError::Island)
            ));
        }
    }

    #[test]
    fn alignment_padding_remains_available_and_is_merged_on_release() {
        let memory = Memory::new();
        let base = memory.address;
        let mut allocator = IslandAllocator::new();
        allocator
            .add_spaces(&[memory.range(4, 0x100)], Scope::Shared)
            .unwrap();
        let aligned = allocator.allocate_near(base, 20, 16).unwrap();
        assert_eq!((aligned.address(), aligned.len), (base + 16, 20));
        assert_eq!(
            allocator.spaces[0].free,
            vec![memory.range(4, 16), memory.range(36, 0x100)]
        );
        let prefix = allocator.allocate_near(base, 12, 4).unwrap();
        assert_eq!(prefix.address(), base + 4);
        unsafe {
            allocator.deallocate(aligned);
            allocator.deallocate(prefix);
        }
        assert_eq!(allocator.spaces[0].free, vec![memory.range(4, 0x100)]);
    }

    #[test]
    fn rejects_invalid_alignment_and_handles_alignment_overflow() {
        let mut allocator = IslandAllocator::new();
        for align in [0, 1, 2, 3, 6, usize::MAX] {
            assert!(matches!(
                allocator.allocate_near(0x1000, 4, align),
                Err(WispError::Island)
            ));
        }
        assert!(allocator.spaces.is_empty());

        let range = usize::MAX - 15..usize::MAX - 3;
        let mut space = Space {
            free: vec![range.clone()],
            range,
            scope: Scope::Shared,
        };
        assert!(space.allocate(usize::MAX - 15, 4, 32).is_none());
        assert_eq!(space.free, vec![usize::MAX - 15..usize::MAX - 3]);
    }

    #[test]
    fn registering_memory_splits_it_at_page_boundaries() {
        let memory = Memory::new();
        let size = page::size();
        let mut allocator = IslandAllocator::new();
        allocator
            .add_spaces(&[memory.range(size - 8, size + 8)], Scope::Shared)
            .unwrap();
        let target = memory.address + size;
        assert_eq!(allocator.spaces.len(), 2);
        assert!(allocator.try_allocate(target, 16, 4).is_none());
        assert_eq!(
            allocator.try_allocate(target, 8, 4).unwrap().address(),
            target - 8
        );
        assert_eq!(
            allocator.try_allocate(target, 8, 4).unwrap().address(),
            target
        );
    }

    #[test]
    fn nearby_mapping_is_reachable_and_does_not_replace_target() {
        let memory = Memory::new();
        let size = page::size();
        let mapped = mman::mmap_near(memory.address, size * 2).unwrap();
        assert_ne!(mapped.start, memory.address);
        assert!(asm::branch_offset(memory.address, mapped.start).is_ok());
        assert_eq!(mapped.start % (size * 2), 0);
        assert_eq!(
            region::query(memory.address as *const u8)
                .unwrap()
                .protection(),
            Protection::READ_EXECUTE
        );
        unsafe { assert_eq!(libc::munmap(mapped.start as _, size), 0) };
    }

    #[test]
    fn new_page_allocations_can_be_recycled() {
        let memory = Memory::new();
        let target = memory.address;
        let size = page::size();
        let mut allocator = IslandAllocator::new();
        let a = allocator.allocate_near(target, 20, 4).unwrap();
        let address = a.address();
        let b = allocator.allocate_near(target, 4, 4).unwrap();
        assert_ne!(b.address(), address);
        unsafe { allocator.deallocate(a) };
        let c = allocator.allocate_near(target, 20, 4).unwrap();
        assert_eq!(c.address(), address);
        assert_eq!(allocator.spaces.len(), 1);
        let full_page = allocator.allocate_near(target, size, 4).unwrap();
        assert_eq!(full_page.len, size);
        assert_eq!(full_page.address() % size, 0);
        assert_eq!(allocator.spaces.len(), 2);
        unsafe {
            allocator.deallocate(b);
            allocator.deallocate(c);
            allocator.deallocate(full_page);
            for space in allocator.spaces {
                assert_eq!(libc::munmap(space.range.start as _, size), 0);
            }
        }
    }
}
