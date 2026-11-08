use crate::asm::{Assemble, PATCH_LEN, arm64asm};
#[doc(hidden)]
pub use crate::context::take_original as __take_original;
use crate::island::Island;
use crate::registry::{HOOKS, Registry};
pub use crate::result::{WispError, WispResult};
use core::slice;
use core::sync::atomic::{Ordering, compiler_fence};
use dynasmrt::aarch64::Assembler;
use dynasmrt::{DynasmApi, ExecutableBuffer, cache_control};
use libc::c_long;
use std::ffi::c_void;
use std::{mem, ptr};

mod align;
mod asm;
mod context;
mod elf;
mod errno;
mod island;
mod mman;
mod registry;
mod relocate;
mod result;

#[cfg(test)]
mod tests;

pub struct Stub {
    target: *const c_void,
    entry_patch: [u8; PATCH_LEN],
    backup_insn: Vec<u8>,
    buffers: Vec<ExecutableBuffer>,
    island: Option<Island>,
}

impl Stub {
    unsafe fn install(
        hooks: &mut Registry,
        target: *const c_void,
        backup_insn: Vec<u8>,
        buffers: Vec<ExecutableBuffer>,
        destination: *const c_void,
    ) -> WispResult<Self> {
        let island_body = asm::absolute_branch(destination)?;
        let island = hooks
            .islands
            .allocate_near(target as usize, island_body.len(), PATCH_LEN)?;
        let island_address = island.address();
        let entry_patch = match asm::relative_branch(target as usize, island_address) {
            Ok(entry_patch) => entry_patch,
            Err(error) => {
                unsafe { hooks.islands.deallocate(island) };
                return Err(error);
            }
        };

        hooks.insert(target as usize);

        let stub = Self {
            target,
            entry_patch,
            backup_insn,
            buffers,
            island: Some(island),
        };

        // A failed write may have installed all or part of the patch.
        unsafe {
            compiler_fence(Ordering::SeqCst);

            // Allocator memory stays RWX; synchronize the island before publishing the entry branch.
            ptr::copy_nonoverlapping(
                island_body.as_ptr(),
                island_address as *mut u8,
                island_body.len(),
            );
            cache_control::synchronize_icache(slice::from_raw_parts(
                island_address as *const u8,
                island_body.len(),
            ));

            let result = mman::write_memory(target.cast_mut(), &entry_patch);
            let entry = slice::from_raw_parts(target.cast::<u8>(), entry_patch.len());

            cache_control::synchronize_icache(entry);
            // Cache invalidation must be followed by a local instruction synchronization barrier.
            cache_control::prepare_for_execution(entry);
            compiler_fence(Ordering::SeqCst);

            if let Err(err) = result {
                // A changed entry may still reference the island and trampoline buffers.
                if slice::from_raw_parts(target.cast::<u8>(), entry_patch.len()) == stub.backup_insn
                {
                    hooks.remove(target as usize);

                    let mut stub = stub;

                    hooks.islands.deallocate(stub.island.take().unwrap());
                    stub.buffers.clear();
                }

                return Err(err);
            }
        }

        Ok(stub)
    }

    pub fn target(&self) -> *const c_void {
        self.target
    }

    /// Restores the target function and releases its executable buffers.
    ///
    /// # Safety
    ///
    /// The caller must ensure that neither the target function nor its proxy,
    /// callback or trampolines are being executed by other threads during restoration.
    /// No original function pointer may be used after its buffer is released.
    /// Cross-instance patching and module lifetimes must be coordinated externally.
    ///
    /// If restoration fails, the reservation and executable buffers remain retained.
    pub unsafe fn unhook(mut self) -> WispResult<()> {
        let mut hooks = HOOKS.lock();
        let current_entry =
            unsafe { slice::from_raw_parts(self.target.cast::<u8>(), self.backup_insn.len()) };

        if !hooks.contains(self.target as usize) || current_entry != self.entry_patch {
            return Err(WispError::PatchMismatch);
        }

        unsafe {
            compiler_fence(Ordering::SeqCst);

            let result = mman::write_memory(self.target.cast_mut(), &self.backup_insn);
            let entry = slice::from_raw_parts(self.target.cast::<u8>(), self.backup_insn.len());

            cache_control::synchronize_icache(entry);
            cache_control::prepare_for_execution(entry);
            compiler_fence(Ordering::SeqCst);
            result?;
        }

        hooks.remove(self.target as usize);
        unsafe { hooks.islands.deallocate(self.island.take().unwrap()) };
        self.buffers.clear();

        Ok(())
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        // The installed hook may still reference these buffers.
        for buffer in self.buffers.drain(..) {
            mem::forget(buffer);
        }
    }
}

/// Management operations are serialized per linked Wisp instance.
/// Separate statically linked copies must be coordinated by the caller.
#[derive(Copy, Clone)]
pub struct Wisp;

impl Wisp {
    /// Releases cached private island spaces for the module containing `address`.
    /// Does not unload the module, unmap its memory, or restore page protections.
    /// Shared island pages are retained. An unregistered module is a no-op.
    /// Returns `ModuleInUse` if any of its private spaces still has allocated islands.
    /// Call only after the module has been unloaded.
    ///
    /// # Safety
    ///
    /// - The module must already be unloaded. `address` must be an address saved from within it.
    /// - Before unloading, the caller must unhook all related hooks and ensure
    ///   that no related code is executing or referenced, including islands in shared pages.
    /// - The caller must coordinate hook operations and module loading/unloading so that
    ///   the old module's address ranges are not reused before cleanup completes.
    pub unsafe fn release_module(address: *const c_void) -> WispResult<()> {
        HOOKS.lock().islands.release_module(address as usize)
    }

    /// Replaces the target function with a proxy function.
    ///
    /// # Safety
    ///
    /// - `target_fn` and `proxy_fn` must point to valid function entries.
    /// - The caller must ensure that the target function is not being executed by other threads
    ///   simultaneously to avoid race conditions during the patching process.
    pub unsafe fn replace_fn(
        target_fn: *const c_void,
        proxy_fn: *const c_void,
    ) -> WispResult<Stub> {
        let mut hooks = HOOKS.lock();

        hooks.check(target_fn as usize)?;

        let backup_region = unsafe { slice::from_raw_parts(target_fn.cast::<u8>(), PATCH_LEN) };
        let backup_insn = {
            let mut backup = Vec::new();
            backup.extend_from_slice(backup_region);
            backup
        };

        unsafe { Stub::install(&mut hooks, target_fn, backup_insn, Vec::new(), proxy_fn) }
    }

    /// Hooks the target function, allowing the proxy function to call the original implementation.
    /// The proxy receives the entry GPRs and SP/LR unchanged, except for x17.
    /// As with interception, SIMD and status registers are not explicitly saved.
    ///
    /// # Safety
    ///
    /// - `target_fn` and `proxy_fn` must point to valid function entries.
    /// - `backup_orig` must be a valid mutable reference to a pointer.
    /// - If a proxy uses `orig_fn!`, it must call it once at the beginning, before
    ///   any call that could enter another hook. The macro must come from the
    ///   same linked Wisp instance as the hook.
    /// - The target must allow x17 to be clobbered at entry and trampoline resumption.
    /// - The target and proxy must use the base AAPCS64 calling convention.
    ///   Hooking TLS or allocator routines used internally by Wisp is unsupported.
    /// - The caller must ensure that the target function is not being executed by other threads
    ///   simultaneously to avoid race conditions during the patching process.
    pub unsafe fn hook_fn(
        target_fn: *const c_void,
        proxy_fn: *const c_void,
        backup_orig: Option<&mut *const c_void>,
    ) -> WispResult<Stub> {
        let mut hooks = HOOKS.lock();

        hooks.check(target_fn as usize)?;

        let backup_region = unsafe { slice::from_raw_parts(target_fn.cast::<u8>(), PATCH_LEN) };

        let backup_insn = {
            let mut backup = Vec::new();
            backup.extend_from_slice(backup_region);
            backup
        };

        let (buffer, trampoline) = unsafe {
            let target_next = target_fn.byte_add(PATCH_LEN);
            let proxy_fn = proxy_fn as usize;

            let mut ops = Assembler::new()?;

            arm64asm!(ops
                // pre-orig trampoline
                ; orig:
            );

            relocate::emit(
                &mut ops,
                u32::from_le_bytes(backup_insn[..].try_into().unwrap()),
                target_fn as usize,
            )?;

            arm64asm!(ops
                ; ldr ip, #8
                ; ret ip  // The resume page may still enforce BTI.
                ;; ops.push_u64(target_next as _)
            );

            let trampoline = ops.offset();

            arm64asm!(ops
                // match intercept's GPR protection; x17 remains the branch scratch register.
                ; sub sp, sp, #0xf0
                ; stp fp, lr, [sp]
                ; mov fp, sp
                ; stp x0, x1, [sp, #0x10]
                ; stp x2, x3, [sp, #0x20]
                ; stp x4, x5, [sp, #0x30]
                ; stp x6, x7, [sp, #0x40]
                ; stp x8, x9, [sp, #0x50]
                ; stp x10, x11, [sp, #0x60]
                ; stp x12, x13, [sp, #0x70]
                ; stp x14, x15, [sp, #0x80]
                ; stp x16, x18, [sp, #0x90]
                ; stp x19, x20, [sp, #0xa0]
                ; stp x21, x22, [sp, #0xb0]
                ; stp x23, x24, [sp, #0xc0]
                ; stp x25, x26, [sp, #0xd0]
                ; stp x27, x28, [sp, #0xe0]
                // shortcut: TLS helpers must leave SIMD untouched; recheck libc/toolchain upgrades.
                ; adr x0, <orig
                ; ldr ip, >set_original
                ; blr ip
                ; ldp x27, x28, [sp, #0xe0]
                ; ldp x25, x26, [sp, #0xd0]
                ; ldp x23, x24, [sp, #0xc0]
                ; ldp x21, x22, [sp, #0xb0]
                ; ldp x19, x20, [sp, #0xa0]
                ; ldp x16, x18, [sp, #0x90]
                ; ldp x14, x15, [sp, #0x80]
                ; ldp x12, x13, [sp, #0x70]
                ; ldp x10, x11, [sp, #0x60]
                ; ldp x8, x9, [sp, #0x50]
                ; ldp x6, x7, [sp, #0x40]
                ; ldp x4, x5, [sp, #0x30]
                ; ldp x2, x3, [sp, #0x20]
                ; ldp x0, x1, [sp, #0x10]
                ; ldp fp, lr, [sp]
                ; add sp, sp, #0xf0
                ; ldr ip, >proxy
                ; br ip
                ; proxy:
                ;; ops.push_u64(proxy_fn as _)
                ; set_original:
                ;; ops.push_u64(context::set_original as *const () as _)
            );

            (ops.assemble()?, trampoline)
        };

        let destination = buffer.ptr(trampoline).cast::<c_void>();
        let original = buffer.as_ptr().cast::<c_void>();

        context::initialize()?;

        let stub = unsafe {
            Stub::install(
                &mut hooks,
                target_fn,
                backup_insn,
                vec![buffer],
                destination,
            )?
        };

        if let Some(backup_orig) = backup_orig {
            *backup_orig = original;
        }

        Ok(stub)
    }

    /// Intercepts the target function, calling the callback with a pointer to the saved x0–x7 registers.
    ///
    /// # Safety
    ///
    /// - `target_fn` must point to a valid function entry.
    /// - The target must allow x17 to be clobbered at entry and trampoline resumption.
    /// - The target function must not be executing on other threads during patching.
    /// - Incorrect argument modifications by the callback can lead to undefined behavior.
    pub unsafe fn intercept_fn(
        target_fn: *const c_void,
        callback_fn: extern "C" fn(*mut c_long),
    ) -> WispResult<Stub> {
        let mut hooks = HOOKS.lock();

        hooks.check(target_fn as usize)?;

        let backup_region = unsafe { slice::from_raw_parts(target_fn.cast::<u8>(), PATCH_LEN) };

        let backup_insn = {
            let mut backup = Vec::new();
            backup.extend_from_slice(backup_region);
            backup
        };

        let buffer = unsafe {
            let target_next = target_fn.byte_add(PATCH_LEN);
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

            );

            relocate::emit(
                &mut ops,
                u32::from_le_bytes(backup_insn[..].try_into().unwrap()),
                target_fn as usize,
            )?;

            arm64asm!(ops
                // Jump back to the original function after the patched region
                ; ldr ip, #8
                ; ret ip  // The resume page may still enforce BTI.
                ;; ops.push_u64(target_next as _)
            );

            ops.assemble()?
        };

        let destination = buffer.as_ptr().cast::<c_void>();

        unsafe {
            Stub::install(
                &mut hooks,
                target_fn,
                backup_insn,
                vec![buffer],
                destination,
            )
        }
    }
}
