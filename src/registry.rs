use crate::asm::PATCH_LEN;
use crate::island::IslandAllocator;
use crate::result::{WispError, WispResult};
use parking_lot::Mutex;

pub(crate) static HOOKS: Mutex<Registry> = Mutex::new(Registry::new());

pub(crate) struct Registry {
    targets: Vec<usize>,
    pub(crate) islands: IslandAllocator,
}

impl Registry {
    const fn new() -> Self {
        Self {
            targets: Vec::new(),
            islands: IslandAllocator::new(),
        }
    }

    pub(crate) fn check(&self, target: usize) -> WispResult<()> {
        if target == 0 || !target.is_multiple_of(PATCH_LEN) {
            return Err(WispError::InvalidAddress);
        }

        if self.targets.contains(&target) {
            return Err(WispError::Conflict);
        }

        Ok(())
    }

    pub(crate) fn insert(&mut self, target: usize) {
        self.targets.push(target);
    }

    pub(crate) fn contains(&self, target: usize) -> bool {
        self.targets.contains(&target)
    }

    pub(crate) fn remove(&mut self, target: usize) {
        self.targets.retain(|&other| other != target);
    }
}

#[cfg(test)]
mod tests {
    use super::Registry;
    use crate::result::WispError;
    use parking_lot::Mutex;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn rejects_overlapping_ranges_but_allows_adjacent_ranges() {
        let mut registry = Registry::new();
        registry.insert(0x1000);

        assert!(matches!(registry.check(0x1000), Err(WispError::Conflict)));

        assert!(registry.check(0xffc).is_ok());
        assert!(registry.check(0x1004).is_ok());
    }

    #[test]
    fn removal_releases_only_the_selected_range() {
        let mut registry = Registry::new();
        registry.insert(0x1000);
        registry.insert(0x1010);
        registry.remove(0x1000);

        assert!(!registry.contains(0x1000));
        assert!(registry.check(0x1000).is_ok());
        assert!(registry.contains(0x1010));
        assert!(matches!(registry.check(0x1010), Err(WispError::Conflict)));
        registry.insert(0x1000);
        assert!(registry.contains(0x1000));
    }

    #[test]
    fn rejects_invalid_addresses() {
        let registry = Registry::new();
        for target in [0, 1, 0x1001] {
            assert!(matches!(
                registry.check(target),
                Err(WispError::InvalidAddress)
            ));
            assert!(!registry.contains(target));
        }
    }

    #[test]
    fn concurrent_reservations_have_one_winner() {
        let registry = Arc::new(Mutex::new(Registry::new()));
        let barrier = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let mut registry = registry.lock();
                    match registry.check(0x1000) {
                        Ok(()) => {
                            registry.insert(0x1000);
                            true
                        }
                        Err(WispError::Conflict) => false,
                        Err(err) => panic!("unexpected reservation error: {err}"),
                    }
                })
            })
            .collect();

        let winners = threads
            .into_iter()
            .map(|thread| usize::from(thread.join().unwrap()))
            .sum::<usize>();
        assert_eq!(winners, 1);
    }
}
