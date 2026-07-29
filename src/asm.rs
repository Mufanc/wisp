use crate::result::{WispError, WispResult};
use dynasmrt::aarch64::{Aarch64Relocation, Assembler};
use dynasmrt::{ExecutableBuffer, VecAssembler};
use std::ffi::c_void;

pub(crate) const BRANCH_LEN: usize = 16;

pub(crate) trait Assemble<T> {
    fn assemble(self) -> WispResult<T>;
}

impl Assemble<ExecutableBuffer> for Assembler {
    fn assemble(self) -> WispResult<ExecutableBuffer> {
        self.finalize().map_err(|_| WispError::Dynasm)
    }
}

impl Assemble<Vec<u8>> for VecAssembler<Aarch64Relocation> {
    fn assemble(self) -> WispResult<Vec<u8>> {
        self.finalize().map_err(|_| WispError::Dynasm)
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

pub(crate) fn branch_to(addr: *const c_void) -> WispResult<Vec<u8>> {
    let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(0);

    arm64asm!(ops
        ; ldr ip, #8
        ; br ip
        ;; ops.push_u64(addr as _)
    );

    ops.assemble()
}
