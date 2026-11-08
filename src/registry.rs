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

    #[test]
    fn rejects_occupied_addresses_but_allows_adjacent_instructions() {
        let mut registry = Registry::new();
        registry.insert(0x1000);

        assert!(matches!(registry.check(0x1000), Err(WispError::Conflict)));

        assert!(registry.check(0xffc).is_ok());
        assert!(registry.check(0x1004).is_ok());
    }

    #[test]
    fn removal_releases_only_the_selected_address() {
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
}
