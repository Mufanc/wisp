use crate::asm::{Assemble, BRANCH_LEN, arm64asm};
pub use crate::result::{WispError, WispResult};
use core::slice;
use core::sync::atomic::{Ordering, compiler_fence};
use dynasmrt::aarch64::Assembler;
use dynasmrt::{DynasmApi, ExecutableBuffer, cache_control};
use log::warn;
use region::Region;
use std::ffi::c_void;
use std::marker::PhantomData;
use libc::c_long;

mod align;
mod asm;
mod errno;
mod mman;
mod result;

#[cfg(test)]
mod tests;

pub trait Unhooker: Sized {
    fn unhook(stub: &Stub<Self>) -> WispResult<()>;
}

pub struct SimpleUnhooker;

impl Unhooker for SimpleUnhooker {
    fn unhook(stub: &Stub<Self>) -> WispResult<()> {
        unsafe {
            compiler_fence(Ordering::SeqCst);
            mman::write_memory(stub.target, &stub.backup_insn)?;
            cache_control::synchronize_icache(slice::from_raw_parts(
                stub.target as _,
                stub.backup_insn.len(),
            ));
            compiler_fence(Ordering::SeqCst);
        }

        Ok(())
    }
}

pub struct Stub<U: Unhooker> {
    target: *const c_void,
    backup_insn: Vec<u8>,
    region: Region,
    _buffers: Vec<ExecutableBuffer>,
    _fake: PhantomData<fn(U) -> U>,
}

impl<U: Unhooker> Stub<U> {
    fn new(
        target: *const c_void,
        backup_insn: Vec<u8>,
        region: Region,
        buffers: Vec<ExecutableBuffer>,
    ) -> Self {
        Self {
            target,
            backup_insn,
            region,
            _buffers: buffers,
            _fake: PhantomData,
        }
    }

    pub fn target(&self) -> *const c_void {
        self.target
    }

    pub fn backup_insn(&self) -> &[u8] {
        &self.backup_insn
    }

    pub fn region(&self) -> &Region {
        &self.region
    }
}

impl<U: Unhooker> Drop for Stub<U> {
    fn drop(&mut self) {
        if let Err(err) = U::unhook(self) {
            warn!("failed to unhook: {err:?}")
        }
    }
}

#[macro_export]
macro_rules! orig_fn {
    () => {
        unsafe {
            let ptr: *const core::ffi::c_void;
            core::arch::asm!(
                "mov x0, x30",
                "add x0, x0, #8",
                "blr x0",
                out("x0") ptr,
                options(nostack, preserves_flags),
                clobber_abi("C")
            );
            ptr
        }
    };
}

#[derive(Copy, Clone)]
pub struct CustomWisp<U: Unhooker = SimpleUnhooker>(PhantomData<fn(U) -> U>);

impl<U: Unhooker> CustomWisp<U> {
    /// Replaces the target function with a proxy function.
    ///
    /// # Safety
    ///
    /// - `target_fn` and `proxy_fn` must be valid pointers to executable code.
    /// - The caller must ensure that the target function is not being executed by other threads
    ///   simultaneously to avoid race conditions during the patching process.
    pub unsafe fn replace_fn(
        target_fn: *const c_void,
        proxy_fn: *const c_void,
    ) -> WispResult<Stub<U>> {
        let region = region::query(target_fn)?;

        let branch_insn = asm::branch_to(proxy_fn)?;

        let backup_region = unsafe { slice::from_raw_parts(target_fn as _, BRANCH_LEN) };
        let backup_insn = {
            let mut backup = Vec::new();
            backup.extend_from_slice(backup_region);
            backup
        };

        unsafe {
            compiler_fence(Ordering::SeqCst);
            mman::write_memory(target_fn, &branch_insn)?;
            cache_control::synchronize_icache(backup_region);
            compiler_fence(Ordering::SeqCst);
        }

        Ok(Stub::new(target_fn, backup_insn, region, Vec::new()))
    }

    /// Hooks the target function, allowing the proxy function to call the original implementation.
    ///
    /// # Safety
    ///
    /// - `target_fn` and `proxy_fn` must be valid pointers to executable code.
    /// - `backup_orig` must be a valid mutable reference to a pointer.
    /// - The caller must ensure that the target function is not being executed by other threads
    ///   simultaneously to avoid race conditions during the patching process.
    pub unsafe fn hook_fn(
        target_fn: *const c_void,
        proxy_fn: *const c_void,
        backup_orig: Option<&mut *const c_void>,
    ) -> WispResult<Stub<U>> {
        let region = region::query(target_fn)?;
        let backup_region = unsafe { slice::from_raw_parts(target_fn as _, BRANCH_LEN) };

        check_before_backup(backup_region)?;

        let backup_insn = {
            let mut backup = Vec::new();
            backup.extend_from_slice(backup_region);
            backup
        };

        let (buffer, trampoline) = unsafe {
            let target_next = target_fn.byte_add(BRANCH_LEN);
            let proxy_fn = proxy_fn as usize;

            let mut ops = Assembler::new()?;

            arm64asm!(ops
                // pre-orig trampoline
                ; orig:
                ;; ops.extend(&backup_insn)  // Fixme: fix adrp etc.
                ; ldr ip, #8
                ; br ip
                ;; ops.push_u64(target_next as _)
            );

            let trampoline = ops.offset();

            arm64asm!(ops
                // pre-proxy trampoline
                ; stp fp, lr, [sp, #-16]!
                ; mov fp, sp
                ; movz ip, #(proxy_fn & 0xffff) as _
                ; movk ip, #((proxy_fn >> 16) & 0xffff) as _, lsl #16
                ; movk ip, #((proxy_fn >> 32) & 0xffff) as _, lsl #32
                ; blr ip
                ; ldp fp, lr, [sp], #16  // <-- return here
                ; ret
                // orig_fn! calls this function
                ; adr x0, <orig
                ; ret
            );

            (ops.assemble()?, trampoline)
        };

        let branch_insn = asm::branch_to(buffer.ptr(trampoline) as _)?;

        unsafe {
            compiler_fence(Ordering::SeqCst);
            mman::write_memory(target_fn, &branch_insn)?;
            cache_control::synchronize_icache(backup_region);
            compiler_fence(Ordering::SeqCst);
        }

        if let Some(backup_orig) = backup_orig {
            *backup_orig = buffer.as_ptr() as _;
        }

        Ok(Stub::new(target_fn, backup_insn, region, vec![buffer]))
    }

    /// Intercepts the target function, calling the callback with a pointer to the stack arguments.
    ///
    /// # Safety
    ///
    /// - `target_fn` and `callback_fn` must be valid pointers to executable code.
    /// - The target function must not be executing on other threads during patching.
    /// - Incorrect argument modifications by the callback can lead to undefined behavior.
    pub unsafe fn intercept_fn(
        target_fn: *const c_void,
        callback_fn: extern "C" fn(*mut c_long)
    ) -> WispResult<Stub<U>> {
        let region = region::query(target_fn)?;
        let backup_region = unsafe { slice::from_raw_parts(target_fn as _, BRANCH_LEN) };

        check_before_backup(backup_region)?;

        let backup_insn = {
            let mut backup = Vec::new();
            backup.extend_from_slice(backup_region);
            backup
        };

        let buffer = unsafe {
            let target_next = target_fn.byte_add(BRANCH_LEN);
            let callback_fn = callback_fn as usize;

            let mut ops = Assembler::new()?;

            arm64asm!(ops
                // Save argument registers x0-x7 to stack
                ; stp x6, x7, [sp, #-16]!
                ; stp x4, x5, [sp, #-16]!
                ; stp x2, x3, [sp, #-16]!
                ; stp x0, x1, [sp, #-16]!

                // Pass pointer to saved registers as first argument to callback
                ; mov x0, sp

                // Save frame pointer and link register (prologue)
                ; stp fp, lr, [sp, #-16]!
                ; mov fp, sp

                // Save all other GPRs (x8-x30)
                ; stp x28, xzr, [sp, #-16]!
                ; stp x26, x27, [sp, #-16]!
                ; stp x24, x25, [sp, #-16]!
                ; stp x22, x23, [sp, #-16]!
                ; stp x20, x21, [sp, #-16]!
                ; stp x18, x19, [sp, #-16]!
                ; stp x16, x17, [sp, #-16]!
                ; stp x14, x15, [sp, #-16]!
                ; stp x12, x13, [sp, #-16]!
                ; stp x10, x11, [sp, #-16]!
                ; stp x8, x9, [sp, #-16]!

                // Call callback_fn with pointer to arguments
                ; movz ip, #(callback_fn & 0xffff) as _
                ; movk ip, #((callback_fn >> 16) & 0xffff) as _, lsl #16
                ; movk ip, #((callback_fn >> 32) & 0xffff) as _, lsl #32
                ; blr ip
                
                // Restore routine GPRs in reverse order
                ; ldp x8, x9, [sp], #16
                ; ldp x10, x11, [sp], #16
                ; ldp x12, x13, [sp], #16
                ; ldp x14, x15, [sp], #16
                ; ldp x16, x17, [sp], #16
                ; ldp x18, x19, [sp], #16
                ; ldp x20, x21, [sp], #16
                ; ldp x22, x23, [sp], #16
                ; ldp x24, x25, [sp], #16
                ; ldp x26, x27, [sp], #16
                ; ldp x28, xzr, [sp], #16

                // Restore frame pointer and link register (epilogue)
                ; ldp fp, lr, [sp], #16

                // Restore argument registers x0-x7 from stack
                ; ldp x0, x1, [sp], #16
                ; ldp x2, x3, [sp], #16
                ; ldp x4, x5, [sp], #16
                ; ldp x6, x7, [sp], #16

                // Execute the original instructions that were replaced
                ;; ops.extend(&backup_insn)
                
                // Jump back to the original function after the patched region
                ; ldr ip, #8
                ; br ip
                ;; ops.push_u64(target_next as _)
            );
            
            ops.assemble()?
        };

        let branch_insn = asm::branch_to(buffer.as_ptr() as _)?;

        unsafe {
            compiler_fence(Ordering::SeqCst);
            mman::write_memory(target_fn, &branch_insn)?;
            cache_control::synchronize_icache(backup_region);
            compiler_fence(Ordering::SeqCst);
        }

        Ok(Stub::new(target_fn, backup_insn, region, vec![buffer]))
    }
}

pub type Wisp = CustomWisp<SimpleUnhooker>;

fn is_pc_rel(insn: u32) -> bool {
    // Branch instructions (B, BL, B_COND)
    (insn & 0xFC000000) == 0x14000000 || // B
    (insn & 0xFF000010) == 0x54000000 || // B_COND
    (insn & 0xFC000000) == 0x94000000 || // BL

    // Address generation instructions (ADR, ADRP)
    (insn & 0x9F000000) == 0x10000000 || // ADR
    (insn & 0x9F000000) == 0x90000000 || // ADRP

    // Literal load instructions (LDR_LIT)
    (insn & 0xFF000000) == 0x18000000 || // LDR_LIT_32
    (insn & 0xFF000000) == 0x58000000 || // LDR_LIT_64
    (insn & 0xFF000000) == 0x98000000 || // LDRSW_LIT
    (insn & 0xFF000000) == 0xD8000000 || // PRFM_LIT
    (insn & 0xFF000000) == 0x1C000000 || // LDR_SIMD_LIT_32
    (insn & 0xFF000000) == 0x5C000000 || // LDR_SIMD_LIT_64
    (insn & 0xFF000000) == 0x9C000000 || // LDR_SIMD_LIT_128

    // Conditional branch instructions (CBZ, CBNZ, TBZ, TBNZ)
    (insn & 0x7F000000) == 0x34000000 || // CBZ
    (insn & 0x7F000000) == 0x35000000 || // CBNZ
    (insn & 0x7F000000) == 0x36000000 || // TBZ
    (insn & 0x7F000000) == 0x37000000    // TBNZ
}

fn check_before_backup(backup_region: &[u8]) -> WispResult<()> {
    let (pf, backup_insn, sf) = unsafe { backup_region.align_to::<u32>() };
    assert!(pf.is_empty() && sf.is_empty());

    if backup_insn.iter().any(|&insn| is_pc_rel(insn)) {
        Err(WispError::NotSupported)
    } else {
        Ok(())
    }
}
