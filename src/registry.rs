use crate::asm::BRANCH_LEN;
use crate::result::{WispError, WispResult};
use parking_lot::Mutex;

pub(crate) static HOOKS: Mutex<Registry> = Mutex::new(Registry::new());

pub(crate) struct Registry {
    targets: Vec<usize>,
}

impl Registry {
    const fn new() -> Self {
        Self {
            targets: Vec::new(),
        }
    }

    pub(crate) fn check(&self, target: usize) -> WispResult<()> {
        let end = target
            .checked_add(BRANCH_LEN)
            .filter(|_| target != 0 && target.is_multiple_of(4))
            .ok_or(WispError::InvalidAddress)?;

        if self
            .targets
            .iter()
            .any(|&other| target < other + BRANCH_LEN && other < end)
        {
            return Err(WispError::Conflict);
        }

        Ok(())
    }

    pub(crate) fn insert(&mut self, target: usize) -> WispResult<()> {
        self.check(target)?;
        self.targets.push(target);
        Ok(())
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
        registry.insert(0x1000).unwrap();

        for target in [0xff4, 0xff8, 0xffc, 0x1000, 0x1004, 0x1008, 0x100c] {
            assert!(matches!(registry.check(target), Err(WispError::Conflict)));
        }

        assert!(registry.check(0xff0).is_ok());
        assert!(registry.check(0x1010).is_ok());
    }

    #[test]
    fn removal_releases_only_the_selected_range() {
        let mut registry = Registry::new();
        registry.insert(0x1000).unwrap();
        registry.insert(0x1010).unwrap();
        registry.remove(0x1000);

        assert!(!registry.contains(0x1000));
        assert!(registry.check(0x1000).is_ok());
        assert!(registry.contains(0x1010));
        assert!(matches!(registry.check(0x1010), Err(WispError::Conflict)));
        registry.insert(0x1000).unwrap();
        assert!(registry.contains(0x1000));
    }

    #[test]
    fn rejects_invalid_ranges() {
        let mut registry = Registry::new();
        for target in [0, 1, 0x1001, usize::MAX - 3] {
            assert!(matches!(
                registry.insert(target),
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
                    match registry.lock().insert(0x1000) {
                        Ok(_) => true,
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
