use crate::asm::BRANCH_LEN;
use crate::result::WispError;
use crate::{Wisp, asm, check_before_backup, orig_fn};
use core::arch::naked_asm;
use core::slice;
use libc::{PROT_EXEC, PROT_READ, PROT_WRITE, c_long};
use region::Protection;
use std::ffi::c_void;
use std::{mem, ptr};

macro_rules! repeat {
    ($n: literal, $($body:tt)*) => {
        for _ in 0..$n {
            $($body)*
        }
    };
}

#[test]
fn test_branch_len() {
    let insn = asm::branch_to(ptr::null_mut()).expect("failed to assemble");
    assert_eq!(insn.len(), BRANCH_LEN);
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
        assert_eq!(target_fn(a, b), proxy_fn(a, b));
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
        unsafe {
            assert_eq!(
                mem::transmute::<*const c_void, fn(i32, i32) -> i32>(ORIG_FN)(a, b),
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
        assert_eq!(target_fn(a, b), proxy_fn(a, b));
    });

    unsafe { stub.unhook().expect("failed to unhook func") }
}

#[test]
fn test_hook_dyn_orig() {
    extern "C" fn target_fn(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        let orig_fn = orig_fn!();

        unsafe {
            assert_eq!(
                mem::transmute::<*const c_void, fn(i32, i32) -> i32>(orig_fn)(a, b),
                a + b
            );
        }

        a * b
    }

    #[allow(static_mut_refs)]
    let stub =
        unsafe { Wisp::hook_fn(target_fn as _, proxy_fn as _, None).expect("failed to hook func") };

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(target_fn(a, b), a * b);
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
        let mut ptr = args as *mut u32;

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

    target_fn(
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

    extern "C" fn hook_target(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        a * b
    }

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(replace_target(a, b), a + b);
        assert_eq!(hook_target(a, b), a + b);
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
        assert_eq!(replace_target(a, b), a * b);
        assert_eq!(hook_target(a, b), a * b);
    });

    unsafe {
        replace_stub.unhook().expect("failed to unhook func");
        hook_stub.unhook().expect("failed to unhook func");
    }

    repeat!(100, {
        let a = fastrand::i32(-1000..1000);
        let b = fastrand::i32(-1000..1000);
        assert_eq!(replace_target(a, b), a + b);
        assert_eq!(hook_target(a, b), a + b);
    });
}

#[test]
fn test_drop_keeps_hook() {
    extern "C" fn target_fn(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        a * b
    }

    let stub =
        unsafe { Wisp::hook_fn(target_fn as _, proxy_fn as _, None).expect("failed to hook func") };

    drop(stub);
    assert_eq!(target_fn(2, 3), 6);
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
        unsafe { mem::transmute::<*const c_void, fn(i32, i32) -> i32>(ORIG_FN_1)(a, b) }
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
        let orig_fn = orig_fn!();
        unsafe { mem::transmute::<*const c_void, fn(i32, i32) -> i32>(orig_fn)(a, b) }
    }

    #[allow(static_mut_refs)]
    unsafe {
        Wisp::hook_fn(target_fn_2 as _, proxy_fn_2 as _, None).expect("failed to hook func");
    }

    target_fn_2(3, 5);
}

#[test]
fn test_verify_insn() {
    #[unsafe(naked)]
    extern "C" fn fn_with_nops() {
        naked_asm!("nop", "nop", "nop", "nop", "ret")
    }

    // Branch instructions
    #[unsafe(naked)]
    extern "C" fn fn_with_b() {
        naked_asm!("b 0", "ret")
    }

    #[unsafe(naked)]
    extern "C" fn fn_with_bl() {
        naked_asm!("bl 0", "ret")
    }

    #[unsafe(naked)]
    extern "C" fn fn_with_b_cond() {
        naked_asm!("b.eq 0", "ret")
    }

    // Address generation instructions
    #[unsafe(naked)]
    extern "C" fn fn_with_adr() {
        naked_asm!("adr x0, 0", "ret")
    }

    #[unsafe(naked)]
    extern "C" fn fn_with_adrp() {
        naked_asm!("adrp x0, 0", "ret")
    }

    // Literal load instructions
    #[unsafe(naked)]
    extern "C" fn fn_with_ldr_lit_32() {
        naked_asm!("ldr w0, 0", "ret")
    }

    #[unsafe(naked)]
    extern "C" fn fn_with_ldr_lit_64() {
        naked_asm!("ldr x0, 0", "ret")
    }

    #[unsafe(naked)]
    extern "C" fn fn_with_ldrsw_lit() {
        naked_asm!("ldrsw x0, 0", "ret")
    }

    #[unsafe(naked)]
    extern "C" fn fn_with_prfm_lit() {
        naked_asm!("prfm pldl1keep, 0", "ret")
    }

    #[unsafe(naked)]
    extern "C" fn fn_with_ldr_simd_lit_32() {
        naked_asm!("ldr s0, 0", "ret")
    }

    #[unsafe(naked)]
    extern "C" fn fn_with_ldr_simd_lit_64() {
        naked_asm!("ldr d0, 0", "ret")
    }

    #[unsafe(naked)]
    extern "C" fn fn_with_ldr_simd_lit_128() {
        naked_asm!("ldr q0, 0", "ret")
    }

    // Compare and branch instructions
    #[unsafe(naked)]
    extern "C" fn fn_with_cbz() {
        naked_asm!("cbz x0, 0", "ret")
    }

    #[unsafe(naked)]
    extern "C" fn fn_with_cbnz() {
        naked_asm!("cbnz x0, 0", "ret")
    }

    #[unsafe(naked)]
    extern "C" fn fn_with_tbz() {
        naked_asm!("tbz x0, #0, 0", "ret")
    }

    #[unsafe(naked)]
    extern "C" fn fn_with_tbnz() {
        naked_asm!("tbnz x0, #0, 0", "ret")
    }

    macro_rules! test_fn {
        ($fn:ident, $expect_ok:expr) => {{
            let region = unsafe { slice::from_raw_parts($fn as *const u8, BRANCH_LEN) };
            if $expect_ok {
                assert!(check_before_backup(region).is_ok(), stringify!($fn));
            } else {
                assert!(
                    matches!(check_before_backup(region), Err(WispError::NotSupported)),
                    stringify!($fn)
                );
            }
        }};
    }

    // Should pass
    test_fn!(fn_with_nops, true);

    // Branch instructions - should reject
    test_fn!(fn_with_b, false);
    test_fn!(fn_with_bl, false);
    test_fn!(fn_with_b_cond, false);

    // Address generation - should reject
    test_fn!(fn_with_adr, false);
    test_fn!(fn_with_adrp, false);

    // Literal loads - should reject
    test_fn!(fn_with_ldr_lit_32, false);
    test_fn!(fn_with_ldr_lit_64, false);
    test_fn!(fn_with_ldrsw_lit, false);
    test_fn!(fn_with_prfm_lit, false);
    test_fn!(fn_with_ldr_simd_lit_32, false);
    test_fn!(fn_with_ldr_simd_lit_64, false);
    test_fn!(fn_with_ldr_simd_lit_128, false);

    // Compare and branch - should reject
    test_fn!(fn_with_cbz, false);
    test_fn!(fn_with_cbnz, false);
    test_fn!(fn_with_tbz, false);
    test_fn!(fn_with_tbnz, false);
}
