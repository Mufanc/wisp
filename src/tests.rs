use crate::asm::{Assemble, PATCH_LEN};
use crate::result::WispError;
use crate::{Wisp, asm, orig_fn};
use core::arch::naked_asm;
use core::slice;
use dynasmrt::aarch64::{Aarch64Relocation, Assembler};
use dynasmrt::{DynasmError, VecAssembler};
use libc::{PROT_EXEC, PROT_READ, PROT_WRITE, c_long};
use region::Protection;
use std::ffi::c_void;
use std::{hint, mem, ptr};

#[cfg(target_os = "android")]
use dynasmrt::ExecutableBuffer;

macro_rules! repeat {
    ($n: literal, $($body:tt)*) => {
        for _ in 0..$n {
            $($body)*
        }
    };
}

#[test]
fn test_branch_len() {
    let insn = asm::absolute_branch(ptr::null_mut()).expect("failed to assemble");
    assert_eq!(insn.len(), 16);
}

#[test]
fn test_relative_branch_boundaries() {
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
            u32::from_le_bytes(asm::relative_branch(from, to).unwrap()),
            expected
        );
    }
    for to in [from - (1 << 27) - 4, from + (1 << 27), usize::MAX - 3] {
        assert!(matches!(
            asm::relative_branch(from, to),
            Err(WispError::Island)
        ));
    }
    for (from, to) in [(from + 1, from), (from, from + 2)] {
        assert!(matches!(
            asm::relative_branch(from, to),
            Err(WispError::InvalidAddress)
        ));
    }
}

#[test]
fn test_assembly_errors_preserve_source() {
    let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(0);
    asm::arm64asm!(ops; b ->missing);
    let err = ops.assemble().unwrap_err();
    assert!(matches!(
        &err,
        WispError::Dynasm(DynasmError::UnknownLabel(_))
    ));
    assert!(std::error::Error::source(&err).is_some());

    let mut ops = Assembler::new().unwrap();
    asm::arm64asm!(ops; b ->missing);
    assert!(matches!(
        ops.assemble(),
        Err(WispError::Dynasm(DynasmError::UnknownLabel(_)))
    ));
}

#[test]
fn test_assembly_with_live_executor() {
    let ops = Assembler::new().unwrap();
    let reader = ops.reader();
    assert!(matches!(ops.assemble(), Err(WispError::AssemblerInUse)));
    drop(reader);
}

#[test]
fn test_region_flags() {
    assert_eq!(Protection::READ.bits() as i32, PROT_READ);
    assert_eq!(Protection::WRITE.bits() as i32, PROT_WRITE);
    assert_eq!(Protection::EXECUTE.bits() as i32, PROT_EXEC);
}

#[test]
fn test_replace() {
    extern "C" fn target_fn(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        a * b
    }

    let stub =
        unsafe { Wisp::replace_fn(target_fn as _, proxy_fn as _).expect("failed to replace func") };

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(
            hint::black_box(target_fn as extern "C" fn(i32, i32) -> i32)(a, b),
            proxy_fn(a, b)
        );
    });

    unsafe { stub.unhook().expect("failed to unhook func") }
}

#[test]
fn test_hook() {
    static mut ORIG_FN: *const c_void = ptr::null_mut();

    extern "C" fn target_fn(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        let original = unsafe { orig_fn!() };

        unsafe {
            let saved_original = ORIG_FN;
            assert_eq!(original, saved_original);
            assert_eq!(
                mem::transmute::<*const c_void, extern "C" fn(i32, i32) -> i32>(ORIG_FN)(a, b),
                a + b
            );
        }

        a * b
    }

    #[allow(static_mut_refs)]
    let stub = unsafe {
        Wisp::hook_fn(target_fn as _, proxy_fn as _, Some(&mut ORIG_FN))
            .expect("failed to hook func")
    };

    assert!(unsafe { !ORIG_FN.is_null() });

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(
            hint::black_box(target_fn as extern "C" fn(i32, i32) -> i32)(a, b),
            a * b
        );
    });

    unsafe { stub.unhook().expect("failed to unhook func") }
}

#[test]
fn test_hook_dyn_orig() {
    extern "C" fn target_fn(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        let original = unsafe { orig_fn!(unsafe extern "C" fn(i32, i32) -> i32) };

        assert_eq!(unsafe { original(a, b) }, a + b);

        a * b
    }

    #[allow(static_mut_refs)]
    let stub =
        unsafe { Wisp::hook_fn(target_fn as _, proxy_fn as _, None).expect("failed to hook func") };

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(
            hint::black_box(target_fn as extern "C" fn(i32, i32) -> i32)(a, b),
            a * b
        );
    });

    unsafe { stub.unhook().expect("failed to unhook func") }
}

#[test]
fn test_intercept() {
    extern "C" fn target_fn(
        a: u32,
        b: u32,
        c: u32,
        d: u32,
        e: u32,
        f: u32,
        g: u32,
        h: u32,
        i: u32,
        j: u32,
    ) {
        assert_eq!(a, 0xAAAABBBB);
        assert_eq!(b, 0xAA55AA55);
        assert_eq!(c, 0xDEADBEEF);
        assert_eq!(d, 0x12345678);
        assert_eq!(e, 0x88888888);
        assert_eq!(f, 0xFEE1DEAD);
        assert_eq!(g, 0x11223344);
        assert_eq!(h, 0x55667788);
        assert_eq!(i, 0x99AABBCC);
        assert_eq!(j, 0xFFFFFFFF);
    }

    extern "C" fn callback_fn(args: *mut c_long) {
        let mut ptr = args.cast::<u32>();

        for _ in 0..10 {
            unsafe {
                *ptr = !*ptr;
                ptr = ptr.byte_add(8);
            }
        }
    }

    let stub = unsafe {
        Wisp::intercept_fn(target_fn as _, callback_fn).expect("failed to intercept func")
    };

    hint::black_box(target_fn as extern "C" fn(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32))(
        0x55554444, 0x55AA55AA, 0x21524110, 0xEDCBA987, 0x77777777, 0x011E2152, 0xEEDDCCBB,
        0xAA998877, 0x66554433, 0x00000000,
    );

    unsafe { stub.unhook().expect("failed to unhook func") }
}

#[test]
fn test_unhook() {
    extern "C" fn replace_target(a: i32, b: i32) -> i32 {
        a + b
    }

    // Distinct code keeps the two simultaneously hooked targets from being merged.
    #[unsafe(naked)]
    extern "C" fn hook_target(_: i32, _: i32) -> i32 {
        naked_asm!("nop", "nop", "add w0, w0, w1", "ret");
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        a * b
    }

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(
            hint::black_box(replace_target as extern "C" fn(i32, i32) -> i32)(a, b),
            a + b
        );
        assert_eq!(
            hint::black_box(hook_target as extern "C" fn(i32, i32) -> i32)(a, b),
            a + b
        );
    });

    let replace_stub = unsafe {
        Wisp::replace_fn(replace_target as _, proxy_fn as _).expect("failed to replace func")
    };

    let mut orig_fn: *const c_void = ptr::null_mut();
    let hook_stub = unsafe {
        Wisp::hook_fn(hook_target as _, proxy_fn as _, Some(&mut orig_fn))
            .expect("failed to hook func")
    };

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(
            hint::black_box(replace_target as extern "C" fn(i32, i32) -> i32)(a, b),
            a * b
        );
        assert_eq!(
            hint::black_box(hook_target as extern "C" fn(i32, i32) -> i32)(a, b),
            a * b
        );
    });

    unsafe {
        replace_stub.unhook().expect("failed to unhook func");
        hook_stub.unhook().expect("failed to unhook func");
    }

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(
            hint::black_box(replace_target as extern "C" fn(i32, i32) -> i32)(a, b),
            a + b
        );
        assert_eq!(
            hint::black_box(hook_target as extern "C" fn(i32, i32) -> i32)(a, b),
            a + b
        );
    });
}

#[test]
fn test_drop_keeps_hook() {
    // Keep the intentionally retained hook on code that cannot merge with other test targets.
    #[unsafe(naked)]
    extern "C" fn target_fn(_: i32, _: i32) -> i32 {
        naked_asm!("nop", "add w0, w0, w1", "ret");
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        a * b
    }

    let stub =
        unsafe { Wisp::hook_fn(target_fn as _, proxy_fn as _, None).expect("failed to hook func") };

    drop(stub);
    assert_eq!(
        hint::black_box(target_fn as extern "C" fn(i32, i32) -> i32)(2, 3),
        6
    );
    assert!(matches!(
        unsafe { Wisp::replace_fn(target_fn as _, proxy_fn as _) },
        Err(WispError::Conflict)
    ));
}

#[cfg(target_os = "android")]
fn patch_target() -> ExecutableBuffer {
    let mut ops = Assembler::new().unwrap();
    for _ in 0..8 {
        ops.extend(&0xd503201fu32.to_le_bytes()); // NOP
    }
    ops.extend(&0xd65f03c0u32.to_le_bytes()); // RET
    ops.finalize().unwrap()
}

#[cfg(target_os = "android")]
extern "C" fn unused_callback(_: *mut c_long) {}

#[cfg(target_os = "android")]
#[test]
fn test_conflicts_across_install_methods() {
    let target = patch_target();
    let ptr = target.as_ptr().cast::<c_void>();
    let stub = unsafe { Wisp::hook_fn(ptr, ptr, None).unwrap() };

    assert!(matches!(
        unsafe { Wisp::replace_fn(ptr, ptr) },
        Err(WispError::Conflict)
    ));
    assert!(matches!(
        unsafe { Wisp::hook_fn(ptr, ptr, None) },
        Err(WispError::Conflict)
    ));
    assert!(matches!(
        unsafe { Wisp::intercept_fn(ptr, unused_callback) },
        Err(WispError::Conflict)
    ));
    let adjacent = unsafe { Wisp::replace_fn(ptr.byte_add(PATCH_LEN), ptr).unwrap() };
    unsafe { adjacent.unhook().unwrap() };
    unsafe { stub.unhook().unwrap() };

    let stub = unsafe { Wisp::intercept_fn(ptr, unused_callback).unwrap() };
    unsafe { stub.unhook().unwrap() };
    let stub = unsafe { Wisp::replace_fn(ptr, ptr).unwrap() };
    unsafe { stub.unhook().unwrap() };
}

#[cfg(target_os = "android")]
#[test]
fn test_concurrent_installs() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let target = patch_target();
    let address = target.as_ptr() as usize;
    let start = Arc::new(Barrier::new(8));
    let installed = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let start = Arc::clone(&start);
            let installed = Arc::clone(&installed);
            thread::spawn(move || {
                let ptr = address as *const c_void;
                start.wait();
                let result = unsafe { Wisp::replace_fn(ptr, ptr) };
                installed.wait();
                match result {
                    Ok(stub) => {
                        unsafe { stub.unhook().unwrap() };
                        1
                    }
                    Err(WispError::Conflict) => 0,
                    Err(err) => panic!("unexpected install error: {err}"),
                }
            })
        })
        .collect();
    let winners: usize = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .sum();
    assert_eq!(winners, 1);
    let stub = unsafe { Wisp::replace_fn(address as _, address as _).unwrap() };
    unsafe { stub.unhook().unwrap() };
}

#[cfg(target_os = "android")]
#[test]
fn test_unhook_rejects_changed_patch() {
    for byte in 0..PATCH_LEN {
        let target = patch_target();
        let ptr = target.as_ptr().cast::<c_void>();
        let stub = unsafe { Wisp::replace_fn(ptr, ptr).unwrap() };
        let mut changed = stub.entry_patch;
        changed[byte] ^= 1;
        unsafe { crate::mman::write_memory(ptr.cast_mut(), &changed).unwrap() };

        assert!(matches!(
            unsafe { stub.unhook() },
            Err(WispError::PatchMismatch)
        ));
        assert_eq!(
            unsafe { slice::from_raw_parts(ptr.cast::<u8>(), PATCH_LEN) },
            changed
        );
        assert!(matches!(
            unsafe { Wisp::replace_fn(ptr, ptr) },
            Err(WispError::Conflict)
        ));

        crate::registry::HOOKS.lock().remove(ptr as usize);
    }
}

#[cfg(target_os = "android")]
#[test]
fn test_rejected_instructions_do_not_reserve_target() {
    let mut ops = Assembler::new().unwrap();
    for _ in 0..4 {
        ops.extend(&0xffffffffu32.to_le_bytes()); // Unallocated encoding.
    }
    let target = ops.finalize().unwrap();
    let ptr = target.as_ptr().cast::<c_void>();

    assert!(matches!(
        unsafe { Wisp::hook_fn(ptr, ptr, None) },
        Err(WispError::NotSupported { .. })
    ));
    assert!(matches!(
        unsafe { Wisp::intercept_fn(ptr, unused_callback) },
        Err(WispError::NotSupported { .. })
    ));
    let stub = unsafe { Wisp::replace_fn(ptr, ptr).unwrap() };
    unsafe { stub.unhook().unwrap() };
}

#[cfg(target_os = "android")]
#[test]
fn test_page_end_patch_does_not_touch_next_page() {
    use libc::{MAP_ANON, MAP_FAILED, MAP_PRIVATE, PROT_NONE};

    let size = region::page::size();
    unsafe {
        let mapping = libc::mmap(
            ptr::null_mut(),
            size * 2,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        );
        assert_ne!(mapping, MAP_FAILED);
        let target = mapping.byte_add(size - PATCH_LEN);
        // A one-instruction RET is a valid function without falling through into the guard page.
        ptr::copy_nonoverlapping(
            0xd65f03c0u32.to_le_bytes().as_ptr(),
            target.cast::<u8>(),
            PATCH_LEN,
        );
        assert_eq!(libc::mprotect(mapping, size, PROT_READ | PROT_EXEC), 0);
        assert_eq!(libc::mprotect(mapping.byte_add(size), size, PROT_NONE), 0);

        for method in 0..3 {
            let stub = match method {
                0 => Wisp::replace_fn(target, unused_callback as *const c_void),
                1 => Wisp::hook_fn(target, unused_callback as *const c_void, None),
                _ => Wisp::intercept_fn(target, unused_callback),
            }
            .unwrap();
            assert_eq!(ptr::read(target.cast::<u32>()) & 0xfc000000, 0x14000000);
            stub.unhook().unwrap();
            assert_eq!(ptr::read(target.cast::<u32>()), 0xd65f03c0);
            assert_eq!(
                region::query(target).unwrap().protection(),
                Protection::READ_EXECUTE
            );
            assert_eq!(
                region::query(mapping.byte_add(size)).unwrap().protection(),
                Protection::NONE
            );
        }

        assert_eq!(libc::munmap(mapping, size * 2), 0);
    }
}

#[cfg(target_os = "android")]
#[test]
#[allow(clippy::too_many_arguments)]
fn test_replace_preserves_stack_arguments() {
    #[unsafe(naked)]
    unsafe extern "C" fn target(
        _: i64,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
    ) -> i64 {
        naked_asm!(
            "nop",
            "ldr x0, [sp]",
            "ldr x1, [sp, #8]",
            "add x0, x0, x1",
            "ret"
        );
    }
    #[unsafe(naked)]
    unsafe extern "C" fn proxy(
        _: i64,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
    ) -> i64 {
        naked_asm!("ldr x0, [sp]", "ldr x1, [sp, #8]", "mul x0, x0, x1", "ret");
    }
    let call = std::hint::black_box(
        target as unsafe extern "C" fn(i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) -> i64,
    );
    unsafe {
        assert_eq!(call(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), 19);
        let stub = Wisp::replace_fn(target as *const c_void, proxy as *const c_void).unwrap();
        assert_eq!(call(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), 90);
        stub.unhook().unwrap();
        assert_eq!(call(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), 19);
    }
}

#[test]
#[ignore]
fn test_unwind() {
    static mut ORIG_FN_1: *const c_void = ptr::null_mut();

    extern "C" fn target_fn_1(a: i32, b: i32) -> i32 {
        unsafe {
            libc::raise(35);
        }
        a + b
    }

    extern "C" fn proxy_fn_1(a: i32, b: i32) -> i32 {
        unsafe { mem::transmute::<*const c_void, extern "C" fn(i32, i32) -> i32>(ORIG_FN_1)(a, b) }
    }

    #[allow(static_mut_refs)]
    unsafe {
        Wisp::hook_fn(target_fn_1 as _, proxy_fn_1 as _, Some(&mut ORIG_FN_1))
            .expect("failed to hook func");
    }

    target_fn_1(3, 5);

    extern "C" fn target_fn_2(a: i32, b: i32) -> i32 {
        unsafe {
            libc::raise(35);
        }
        a + b
    }

    extern "C" fn proxy_fn_2(a: i32, b: i32) -> i32 {
        let original = unsafe { orig_fn!(unsafe extern "C" fn(i32, i32) -> i32) };
        unsafe { original(a, b) }
    }

    #[allow(static_mut_refs)]
    unsafe {
        Wisp::hook_fn(target_fn_2 as _, proxy_fn_2 as _, None).expect("failed to hook func");
    }

    target_fn_2(3, 5);
}
