use crate::result::{WispError, WispResult};
use libc::{c_int, pthread_key_t};
use std::ffi::c_void;
use std::sync::OnceLock;
use std::{io, process, ptr};

static KEY: OnceLock<Result<pthread_key_t, c_int>> = OnceLock::new();

/// Reads and clears the original function address for the current `hook_fn` proxy.
///
/// With no argument, returns a raw pointer. Pass the target's function pointer
/// type to obtain a callable pointer. No object or exit cleanup is required.
/// Proxies that do not need the address from TLS can omit the macro.
///
/// # Safety
///
/// If used, call once at the beginning of a proxy entered through this Wisp
/// instance, before any call that could enter another hook and overwrite TLS.
/// The supplied function pointer type must match the target's signature and ABI.
/// Do not use the pointer after unhooking.
#[macro_export]
macro_rules! orig_fn {
    () => {
        $crate::__take_original()
    };
    ($signature:ty) => {
        core::mem::transmute::<*const core::ffi::c_void, $signature>($crate::__take_original())
    };
}

/// Reads the current proxy's original address. Used by `orig_fn!`.
///
/// # Safety
///
/// Call at most once per proxy invocation, before any call that could enter
/// another hook. The proxy must use the same Wisp instance as its hook.
/// The returned pointer is valid only until unhooking.
#[doc(hidden)]
pub unsafe fn take_original() -> *const c_void {
    let original = unsafe { libc::pthread_getspecific(key()) }.cast_const();

    set_original(ptr::null());

    original
}

pub(crate) fn initialize() -> WispResult<()> {
    let key = KEY.get_or_init(|| {
        let mut key = 0;
        let error = unsafe { libc::pthread_key_create(&mut key, None) };

        if error == 0 { Ok(key) } else { Err(error) }
    });

    key.map(|_| ())
        .map_err(|error| WispError::Io(io::Error::from_raw_os_error(error)))
}

fn key() -> pthread_key_t {
    *KEY.get().unwrap().as_ref().unwrap()
}

pub(crate) extern "C" fn set_original(original: *const c_void) {
    // The target's arbitrary ABI provides no error return path at execution time.
    if unsafe { libc::pthread_setspecific(key(), original) } != 0 {
        process::abort();
    }
}

#[cfg(test)]
mod tests {
    use crate::Wisp;
    use core::arch::naked_asm;
    use std::ffi::c_void;
    use std::hint;
    use std::sync::Barrier;
    use std::thread;

    fn check_entry_registers(intercept: bool) {
        #[repr(C)]
        #[derive(Clone, Copy, Debug, Default)]
        struct Registers {
            gpr: [u64; 31],
            sp: u64,
            simd: [u128; 32],
        }

        #[unsafe(naked)]
        unsafe extern "C" fn snapshot(_: *mut Registers) {
            naked_asm!(
                "stp x0, x1, [x0]",
                "stp x2, x3, [x0, #0x10]",
                "stp x4, x5, [x0, #0x20]",
                "stp x6, x7, [x0, #0x30]",
                "stp x8, x9, [x0, #0x40]",
                "stp x10, x11, [x0, #0x50]",
                "stp x12, x13, [x0, #0x60]",
                "stp x14, x15, [x0, #0x70]",
                "stp x16, x17, [x0, #0x80]",
                "stp x18, x19, [x0, #0x90]",
                "stp x20, x21, [x0, #0xa0]",
                "stp x22, x23, [x0, #0xb0]",
                "stp x24, x25, [x0, #0xc0]",
                "stp x26, x27, [x0, #0xd0]",
                "stp x28, x29, [x0, #0xe0]",
                "str x30, [x0, #0xf0]",
                "mov x17, sp",
                "str x17, [x0, #{sp}]",
                "stp q0, q1, [x0, #{simd} + 0x0]",
                "stp q2, q3, [x0, #{simd} + 0x20]",
                "stp q4, q5, [x0, #{simd} + 0x40]",
                "stp q6, q7, [x0, #{simd} + 0x60]",
                "stp q8, q9, [x0, #{simd} + 0x80]",
                "stp q10, q11, [x0, #{simd} + 0xa0]",
                "stp q12, q13, [x0, #{simd} + 0xc0]",
                "stp q14, q15, [x0, #{simd} + 0xe0]",
                "stp q16, q17, [x0, #{simd} + 0x100]",
                "stp q18, q19, [x0, #{simd} + 0x120]",
                "stp q20, q21, [x0, #{simd} + 0x140]",
                "stp q22, q23, [x0, #{simd} + 0x160]",
                "stp q24, q25, [x0, #{simd} + 0x180]",
                "stp q26, q27, [x0, #{simd} + 0x1a0]",
                "stp q28, q29, [x0, #{simd} + 0x1c0]",
                "stp q30, q31, [x0, #{simd} + 0x1e0]",
                "ret",
                sp = const std::mem::offset_of!(Registers, sp),
                simd = const std::mem::offset_of!(Registers, simd),
            );
        }

        #[unsafe(naked)]
        unsafe extern "C" fn target(_: *mut Registers) {
            naked_asm!("nop", "b {snapshot}", snapshot = sym snapshot);
        }

        #[unsafe(naked)]
        unsafe extern "C" fn proxy(_: *mut Registers) {
            naked_asm!("b {snapshot}", snapshot = sym snapshot);
        }

        // Clobber caller-saved GPRs without modifying the saved argument slots.
        #[unsafe(naked)]
        extern "C" fn callback(_: *mut libc::c_long) {
            naked_asm!(
                "mov x0, #100",
                "mov x1, #101",
                "mov x2, #102",
                "mov x3, #103",
                "mov x4, #104",
                "mov x5, #105",
                "mov x6, #106",
                "mov x7, #107",
                "mov x8, #108",
                "mov x9, #109",
                "mov x10, #110",
                "mov x11, #111",
                "mov x12, #112",
                "mov x13, #113",
                "mov x14, #114",
                "mov x15, #115",
                "mov x16, #116",
                "ret",
            );
        }

        // Seed the same state at one BLR site while preserving the Rust caller's ABI.
        #[unsafe(naked)]
        unsafe extern "C" fn call(_: *mut Registers, _: *const c_void) {
            naked_asm!(
                "sub sp, sp, #0xf0",
                "stp x19, x20, [sp]",
                "stp x21, x22, [sp, #0x10]",
                "stp x23, x24, [sp, #0x20]",
                "stp x25, x26, [sp, #0x30]",
                "stp x27, x28, [sp, #0x40]",
                "stp x29, x30, [sp, #0x50]",
                "stp q8, q9, [sp, #0x60]",
                "stp q10, q11, [sp, #0x80]",
                "stp q12, q13, [sp, #0xa0]",
                "stp q14, q15, [sp, #0xc0]",
                "str x1, [sp, #0xe0]",
                "mov x1, #1",
                "mov x2, #2",
                "mov x3, #3",
                "mov x4, #4",
                "mov x5, #5",
                "mov x6, #6",
                "mov x7, #7",
                "mov x8, #8",
                "mov x9, #9",
                "mov x10, #10",
                "mov x11, #11",
                "mov x12, #12",
                "mov x13, #13",
                "mov x14, #14",
                "mov x15, #15",
                "mov x16, #16",
                "mov x19, #19",
                "mov x20, #20",
                "mov x21, #21",
                "mov x22, #22",
                "mov x23, #23",
                "mov x24, #24",
                "mov x25, #25",
                "mov x26, #26",
                "mov x27, #27",
                "mov x28, #28",
                "movi v0.16b, #1",
                "movi v1.16b, #2",
                "movi v2.16b, #3",
                "movi v3.16b, #4",
                "movi v4.16b, #5",
                "movi v5.16b, #6",
                "movi v6.16b, #7",
                "movi v7.16b, #8",
                "movi v8.16b, #9",
                "movi v9.16b, #10",
                "movi v10.16b, #11",
                "movi v11.16b, #12",
                "movi v12.16b, #13",
                "movi v13.16b, #14",
                "movi v14.16b, #15",
                "movi v15.16b, #16",
                "movi v16.16b, #17",
                "movi v17.16b, #18",
                "movi v18.16b, #19",
                "movi v19.16b, #20",
                "movi v20.16b, #21",
                "movi v21.16b, #22",
                "movi v22.16b, #23",
                "movi v23.16b, #24",
                "movi v24.16b, #25",
                "movi v25.16b, #26",
                "movi v26.16b, #27",
                "movi v27.16b, #28",
                "movi v28.16b, #29",
                "movi v29.16b, #30",
                "movi v30.16b, #31",
                "movi v31.16b, #32",
                "ldr x17, [sp, #0xe0]",
                "blr x17",
                "ldp q8, q9, [sp, #0x60]",
                "ldp q10, q11, [sp, #0x80]",
                "ldp q12, q13, [sp, #0xa0]",
                "ldp q14, q15, [sp, #0xc0]",
                "ldp x19, x20, [sp]",
                "ldp x21, x22, [sp, #0x10]",
                "ldp x23, x24, [sp, #0x20]",
                "ldp x25, x26, [sp, #0x30]",
                "ldp x27, x28, [sp, #0x40]",
                "ldp x29, x30, [sp, #0x50]",
                "add sp, sp, #0xf0",
                "ret",
            );
        }

        let mut registers = Box::<Registers>::default();
        let address = (&mut *registers) as *mut Registers;
        unsafe { call(address, target as _) };
        let expected = *registers;

        let stub = unsafe {
            if intercept {
                Wisp::intercept_fn(target as _, callback)
            } else {
                Wisp::hook_fn(target as _, proxy as _, None)
            }
            .unwrap()
        };
        unsafe { call(address, target as _) };
        let actual = *registers;
        unsafe { stub.unhook().unwrap() };

        for index in 0..31 {
            if index != 17 {
                assert_eq!(actual.gpr[index], expected.gpr[index], "x{index}");
            }
        }
        assert_eq!(actual.sp, expected.sp);
        if !intercept {
            // Detect TLS library/toolchain changes: the entry intentionally saves only GPRs.
            assert_eq!(actual.simd, expected.simd);
        }
    }

    #[test]
    fn proxy_preserves_gprs_except_x17() {
        check_entry_registers(false);
    }

    #[test]
    fn intercept_preserves_gprs_and_sp_except_x17() {
        check_entry_registers(true);
    }

    #[test]
    #[allow(clippy::too_many_arguments)]
    fn preserves_integer_and_stack_arguments() {
        type Function =
            unsafe extern "C" fn(i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) -> i64;

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
                "add x0, x0, x1",
                "add x0, x0, x2",
                "add x0, x0, x3",
                "add x0, x0, x4",
                "add x0, x0, x5",
                "add x0, x0, x6",
                "add x0, x0, x7",
                "ldp x1, x2, [sp]",
                "add x0, x0, x1",
                "add x0, x0, x2",
                "ret",
            );
        }

        unsafe extern "C" fn proxy(
            a: i64,
            b: i64,
            c: i64,
            d: i64,
            e: i64,
            f: i64,
            g: i64,
            h: i64,
            i: i64,
            j: i64,
        ) -> i64 {
            let original_fn = unsafe { orig_fn!(Function) };
            assert_eq!(
                [a, b, c, d, e, f, g, h, i, j],
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
            );
            unsafe { original_fn(a, b, c, d, e, f, g, h, i, j) + 100 }
        }

        let call = hint::black_box(target as Function);
        unsafe {
            assert_eq!(call(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), 55);
            let stub = Wisp::hook_fn(target as _, proxy as _, None).unwrap();
            for _ in 0..10 {
                assert_eq!(call(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), 155);
                assert!(libc::pthread_getspecific(super::key()).is_null());
            }
            stub.unhook().unwrap();
            assert_eq!(call(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), 55);
        }
    }

    #[test]
    #[allow(clippy::too_many_arguments)]
    fn preserves_float_and_stack_arguments() {
        type Function =
            unsafe extern "C" fn(f64, f64, f64, f64, f64, f64, f64, f64, f64, f64) -> f64;

        #[unsafe(naked)]
        unsafe extern "C" fn target(
            _: f64,
            _: f64,
            _: f64,
            _: f64,
            _: f64,
            _: f64,
            _: f64,
            _: f64,
            _: f64,
            _: f64,
        ) -> f64 {
            naked_asm!(
                "nop",
                "fadd d0, d0, d1",
                "fadd d0, d0, d2",
                "fadd d0, d0, d3",
                "fadd d0, d0, d4",
                "fadd d0, d0, d5",
                "fadd d0, d0, d6",
                "fadd d0, d0, d7",
                "ldp d1, d2, [sp]",
                "fadd d0, d0, d1",
                "fadd d0, d0, d2",
                "ret",
            );
        }

        unsafe extern "C" fn proxy(
            a: f64,
            b: f64,
            c: f64,
            d: f64,
            e: f64,
            f: f64,
            g: f64,
            h: f64,
            i: f64,
            j: f64,
        ) -> f64 {
            let original_fn = unsafe { orig_fn!(Function) };
            assert_eq!(
                [a, b, c, d, e, f, g, h, i, j],
                [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
            );
            unsafe { original_fn(a, b, c, d, e, f, g, h, i, j) + 0.5 }
        }

        let call = hint::black_box(target as Function);
        unsafe {
            assert_eq!(
                call(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0),
                55.0
            );
            let stub = Wisp::hook_fn(target as _, proxy as _, None).unwrap();
            for _ in 0..10 {
                assert_eq!(
                    call(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0),
                    55.5
                );
                assert!(libc::pthread_getspecific(super::key()).is_null());
            }
            stub.unhook().unwrap();
        }
    }

    #[test]
    fn preserves_indirect_structure_return() {
        #[repr(C)]
        #[derive(Debug, PartialEq)]
        struct Output(u64, u64, u64);

        #[unsafe(naked)]
        unsafe extern "C" fn target(_: u64) -> Output {
            naked_asm!(
                "nop",
                "str x0, [x8]",
                "add x0, x0, #1",
                "str x0, [x8, #8]",
                "add x0, x0, #1",
                "str x0, [x8, #16]",
                "ret",
            );
        }

        unsafe extern "C" fn proxy(value: u64) -> Output {
            let original_fn = unsafe { orig_fn!(unsafe extern "C" fn(u64) -> Output) };
            let mut output = unsafe { original_fn(value) };
            output.2 += 100;
            output
        }

        let call = hint::black_box(target as unsafe extern "C" fn(u64) -> Output);
        unsafe {
            assert_eq!(call(7), Output(7, 8, 9));
            let stub = Wisp::hook_fn(target as _, proxy as _, None).unwrap();
            assert_eq!(call(7), Output(7, 8, 109));
            assert!(libc::pthread_getspecific(super::key()).is_null());
            stub.unhook().unwrap();
            assert_eq!(call(7), Output(7, 8, 9));
        }
    }

    #[test]
    fn proxy_receives_callers_return_address_and_stack_pointer() {
        #[repr(C)]
        struct EntryState {
            return_address: usize,
            stack_pointer: usize,
        }

        #[unsafe(naked)]
        unsafe extern "C" fn target() -> EntryState {
            naked_asm!("nop", "mov x0, x30", "mov x1, sp", "ret");
        }

        #[unsafe(naked)]
        unsafe extern "C" fn proxy() -> EntryState {
            naked_asm!("mov x0, x30", "mov x1, sp", "b {body}", body = sym proxy_body);
        }

        extern "C" fn proxy_body(return_address: usize, stack_pointer: usize) -> EntryState {
            let original_fn = unsafe { orig_fn!(unsafe extern "C" fn() -> EntryState) };
            assert_ne!(unsafe { original_fn() }.return_address, 0);
            EntryState {
                return_address,
                stack_pointer,
            }
        }

        #[unsafe(naked)]
        unsafe extern "C" fn call_and_check(_: *const c_void) -> bool {
            naked_asm!(
                "stp x29, x30, [sp, #-16]!",
                "blr x0",
                "2:",
                "adr x2, 2b",
                "cmp x0, x2",
                "cset x0, eq",
                "mov x2, sp",
                "cmp x1, x2",
                "cset x1, eq",
                "and x0, x0, x1",
                "ldp x29, x30, [sp], #16",
                "ret",
            );
        }

        unsafe {
            assert!(call_and_check(target as _));
            let stub = Wisp::hook_fn(target as _, proxy as _, None).unwrap();
            assert!(call_and_check(target as _));
            assert!(libc::pthread_getspecific(super::key()).is_null());
            stub.unhook().unwrap();
        }
    }

    #[test]
    fn shared_proxy_supports_nested_calls_and_early_return() {
        #[unsafe(naked)]
        unsafe extern "C" fn target_a(_: i64) -> i64 {
            naked_asm!("nop", "add x0, x0, #1", "ret");
        }

        #[unsafe(naked)]
        unsafe extern "C" fn target_b(_: i64) -> i64 {
            naked_asm!("nop", "add x0, x0, #10", "ret");
        }

        extern "C" fn proxy(value: i64) -> i64 {
            let original_fn = unsafe { orig_fn!(unsafe extern "C" fn(i64) -> i64) };
            assert!(unsafe { libc::pthread_getspecific(super::key()).is_null() });
            if value < 0 {
                return 100;
            }
            let original = unsafe { original_fn(value) };
            let result = if value > 0 {
                original + unsafe { hint::black_box(target_b)(value - 1) }
            } else {
                original
            };
            assert!(unsafe { libc::pthread_getspecific(super::key()).is_null() });
            assert_eq!(unsafe { original_fn(value) }, original);
            result
        }

        unsafe {
            let first = Wisp::hook_fn(target_a as _, proxy as _, None).unwrap();
            let second = Wisp::hook_fn(target_b as _, proxy as _, None).unwrap();
            for _ in 0..10 {
                assert_eq!(hint::black_box(target_a)(3), 37);
                assert!(libc::pthread_getspecific(super::key()).is_null());
                assert_eq!(hint::black_box(target_b)(3), 46);
                assert!(libc::pthread_getspecific(super::key()).is_null());
                assert_eq!(hint::black_box(target_a)(-1), 100);
                assert!(libc::pthread_getspecific(super::key()).is_null());
            }
            first.unhook().unwrap();
            second.unhook().unwrap();
        }
    }

    #[test]
    fn proxy_can_skip_original_lookup() {
        #[unsafe(naked)]
        unsafe extern "C" fn target_a(_: i64) -> i64 {
            naked_asm!("nop", "add x0, x0, #1", "ret");
        }

        #[unsafe(naked)]
        unsafe extern "C" fn target_b(_: i64) -> i64 {
            naked_asm!("nop", "add x0, x0, #10", "ret");
        }

        extern "C" fn proxy_a(value: i64) -> i64 {
            if value == 0 {
                return 100;
            }
            unsafe { hint::black_box(target_b)(value) + 100 }
        }

        extern "C" fn proxy_b(value: i64) -> i64 {
            let original = unsafe { orig_fn!(unsafe extern "C" fn(i64) -> i64) };
            unsafe { original(value) }
        }

        unsafe {
            let mut original_a = std::ptr::null();
            let first = Wisp::hook_fn(target_a as _, proxy_a as _, Some(&mut original_a)).unwrap();
            let second = Wisp::hook_fn(target_b as _, proxy_b as _, None).unwrap();
            for _ in 0..10 {
                assert_eq!(hint::black_box(target_a)(0), 100);
                assert_eq!(
                    libc::pthread_getspecific(super::key()).cast_const(),
                    original_a
                );
                assert_eq!(hint::black_box(target_a)(1), 111);
                assert!(libc::pthread_getspecific(super::key()).is_null());
            }
            first.unhook().unwrap();
            second.unhook().unwrap();
        }
    }

    #[test]
    fn contexts_are_isolated_between_threads() {
        static BARRIER: Barrier = Barrier::new(8);

        #[unsafe(naked)]
        unsafe extern "C" fn target_a(_: i64) -> i64 {
            naked_asm!("nop", "add x0, x0, #1", "ret");
        }

        #[unsafe(naked)]
        unsafe extern "C" fn target_b(_: i64) -> i64 {
            naked_asm!("nop", "add x0, x0, #10", "ret");
        }

        extern "C" fn proxy(value: i64) -> i64 {
            let original_fn = unsafe { orig_fn!(unsafe extern "C" fn(i64) -> i64) };
            BARRIER.wait();
            assert!(unsafe { libc::pthread_getspecific(super::key()).is_null() });
            unsafe { original_fn(value) }
        }

        unsafe {
            let first = Wisp::hook_fn(target_a as _, proxy as _, None).unwrap();
            let second = Wisp::hook_fn(target_b as _, proxy as _, None).unwrap();
            let threads: Vec<_> = (0..8)
                .map(|index| {
                    thread::spawn(move || {
                        let (target, increment) = if index % 2 == 0 {
                            (target_a as unsafe extern "C" fn(i64) -> i64, 1)
                        } else {
                            (target_b as unsafe extern "C" fn(i64) -> i64, 10)
                        };
                        for value in 0..100 {
                            assert_eq!(target(value), value + increment);
                            assert!(libc::pthread_getspecific(super::key()).is_null());
                        }
                    })
                })
                .collect();
            for thread in threads {
                thread.join().unwrap();
            }
            first.unhook().unwrap();
            second.unhook().unwrap();
        }
    }
}
