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
