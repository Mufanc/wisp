use crate::result::{WispError, WispResult};
use dynasmrt::aarch64::{Aarch64Relocation, Assembler};
use dynasmrt::{ExecutableBuffer, VecAssembler};
use std::ffi::c_void;

pub(crate) const PATCH_LEN: usize = 4;
pub(crate) const BRANCH_RANGE: usize = 1 << 27;

pub(crate) fn branch_offset(from: usize, to: usize) -> WispResult<i32> {
    let offset = to as i128 - from as i128;

    if !from.is_multiple_of(4) || !to.is_multiple_of(4) {
        return Err(WispError::InvalidAddress);
    }

    if !(-(BRANCH_RANGE as i128)..BRANCH_RANGE as i128).contains(&offset) {
        return Err(WispError::Island);
    }

    Ok(offset as i32)
}

pub(crate) trait Assemble<T> {
    fn assemble(self) -> WispResult<T>;
}

impl Assemble<ExecutableBuffer> for Assembler {
    fn assemble(mut self) -> WispResult<ExecutableBuffer> {
        self.commit()?;
        self.finalize().map_err(|_| WispError::AssemblerInUse)
    }
}

impl Assemble<Vec<u8>> for VecAssembler<Aarch64Relocation> {
    fn assemble(self) -> WispResult<Vec<u8>> {
        self.finalize().map_err(WispError::Dynasm)
    }
}

macro_rules! arm64asm {
     ($ops:ident $($t:tt)*) => {
         {
             #[allow(unused_imports)]
             use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};

             dynasm!($ops
                 ; .arch aarch64
                 ; .alias ip, x17
                 ; .alias fp, x29
                 ; .alias lr, x30
                 $($t)*
             )
         }
     }
}

pub(crate) use arm64asm;

pub(crate) fn relative_branch(from: usize, to: usize) -> WispResult<[u8; PATCH_LEN]> {
    let offset = branch_offset(from, to)?;
    let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(from);

    arm64asm!(ops; b offset);

    Ok(ops
        .assemble()?
        .try_into()
        .expect("invalid relative branch length"))
}

pub(crate) fn absolute_branch(to: *const c_void) -> WispResult<Vec<u8>> {
    let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(0);

    arm64asm!(ops
        ; ldr ip, #8
        ; br ip
        ;; ops.push_u64(to as _)
    );

    ops.assemble()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dynasmrt::DynasmError;
    use std::ptr;

    #[test]
    fn branch_len() {
        let insn = super::absolute_branch(ptr::null_mut()).expect("failed to assemble");
        assert_eq!(insn.len(), 16);
    }

    #[test]
    fn relative_branch_boundaries() {
        let from = 0x10000000;
        for (offset, expected) in [
            (0i64, 0x14000000),
            (4, 0x14000001),
            (-4, 0x17ffffff),
            (-(1 << 27), 0x16000000),
            ((1 << 27) - 4, 0x15ffffff),
        ] {
            let to = (from as i64 + offset) as usize;
            assert_eq!(
                u32::from_le_bytes(super::relative_branch(from, to).unwrap()),
                expected
            );
        }
        for to in [from - (1 << 27) - 4, from + (1 << 27), usize::MAX - 3] {
            assert!(matches!(
                super::relative_branch(from, to),
                Err(WispError::Island)
            ));
        }
        for (from, to) in [(from + 1, from), (from, from + 2)] {
            assert!(matches!(
                super::relative_branch(from, to),
                Err(WispError::InvalidAddress)
            ));
        }
    }

    #[test]
    fn assembly_errors_preserve_source() {
        let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(0);
        arm64asm!(ops; b ->missing);
        let err = ops.assemble().unwrap_err();
        assert!(matches!(
            &err,
            WispError::Dynasm(DynasmError::UnknownLabel(_))
        ));
        assert!(std::error::Error::source(&err).is_some());

        let mut ops = Assembler::new().unwrap();
        arm64asm!(ops; b ->missing);
        assert!(matches!(
            ops.assemble(),
            Err(WispError::Dynasm(DynasmError::UnknownLabel(_)))
        ));
    }

    #[test]
    fn assembly_with_live_executor() {
        let ops = Assembler::new().unwrap();
        let reader = ops.reader();
        assert!(matches!(ops.assemble(), Err(WispError::AssemblerInUse)));
        drop(reader);
    }
}
