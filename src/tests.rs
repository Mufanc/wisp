use crate::asm::PATCH_LEN;
use crate::result::WispError;
use crate::{Wisp, orig_fn};
use core::arch::naked_asm;
use core::slice;
use dynasmrt::ExecutableBuffer;
use dynasmrt::aarch64::Assembler;
use libc::{PROT_EXEC, PROT_READ, PROT_WRITE, c_long};
use region::Protection;
use std::ffi::c_void;
use std::{hint, mem, ptr};

#[test]
fn replace_redirects_calls() {
    extern "C" fn target_fn(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        a * b
    }

    let stub =
        unsafe { Wisp::replace_fn(target_fn as _, proxy_fn as _).expect("failed to replace func") };

    for (a, b) in [(0, 0), (2, 3), (-7, 5), (-11, -13)] {
        assert_eq!(
            hint::black_box(target_fn as extern "C" fn(i32, i32) -> i32)(a, b),
            proxy_fn(a, b)
        );
    }

    unsafe { stub.unhook().expect("failed to unhook func") }
}

#[test]
fn hook_exposes_original_pointer() {
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

    for (a, b) in [(0, 0), (2, 3), (-7, 5), (-11, -13)] {
        assert_eq!(
            hint::black_box(target_fn as extern "C" fn(i32, i32) -> i32)(a, b),
            a * b
        );
    }

    unsafe { stub.unhook().expect("failed to unhook func") }
}

#[test]
fn hook_resolves_typed_original_from_tls() {
    extern "C" fn target_fn(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
        let original = unsafe { orig_fn!(unsafe extern "C" fn(i32, i32) -> i32) };

        assert_eq!(unsafe { original(a, b) }, a + b);

        a * b
    }

    let stub =
        unsafe { Wisp::hook_fn(target_fn as _, proxy_fn as _, None).expect("failed to hook func") };

    for (a, b) in [(0, 0), (2, 3), (-7, 5), (-11, -13)] {
        assert_eq!(
            hint::black_box(target_fn as extern "C" fn(i32, i32) -> i32)(a, b),
            a * b
        );
    }

    unsafe { stub.unhook().expect("failed to unhook func") }
}

#[test]
fn intercept_modifies_register_and_stack_arguments() {
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
fn intercept_unhook_restores_behavior_and_stops_callback() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);

    #[unsafe(naked)]
    unsafe extern "C" fn target(_: i64) -> i64 {
        naked_asm!("nop", "add x0, x0, #3", "ret");
    }

    extern "C" fn callback(args: *mut c_long) {
        CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe { *args += 100 };
    }

    let call = hint::black_box(target as unsafe extern "C" fn(i64) -> i64);
    assert_eq!(unsafe { call(7) }, 10);

    for expected_calls in 1..=8 {
        let stub = unsafe { Wisp::intercept_fn(target as _, callback).unwrap() };
        assert_eq!(unsafe { call(7) }, 110);
        assert_eq!(CALLS.load(Ordering::Relaxed), expected_calls);
        unsafe { stub.unhook().unwrap() };
        assert_eq!(unsafe { call(7) }, 10);
        assert_eq!(CALLS.load(Ordering::Relaxed), expected_calls);
    }
}

#[test]
fn unhook_restores_replace_and_hook_targets() {
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

    for (a, b) in [(0, 0), (2, 3), (-7, 5), (-11, -13)] {
        assert_eq!(
            hint::black_box(replace_target as extern "C" fn(i32, i32) -> i32)(a, b),
            a + b
        );
        assert_eq!(
            hint::black_box(hook_target as extern "C" fn(i32, i32) -> i32)(a, b),
            a + b
        );
    }

    let replace_stub = unsafe {
        Wisp::replace_fn(replace_target as _, proxy_fn as _).expect("failed to replace func")
    };

    let mut orig_fn: *const c_void = ptr::null_mut();
    let hook_stub = unsafe {
        Wisp::hook_fn(hook_target as _, proxy_fn as _, Some(&mut orig_fn))
            .expect("failed to hook func")
    };

    for (a, b) in [(0, 0), (2, 3), (-7, 5), (-11, -13)] {
        assert_eq!(
            hint::black_box(replace_target as extern "C" fn(i32, i32) -> i32)(a, b),
            a * b
        );
        assert_eq!(
            hint::black_box(hook_target as extern "C" fn(i32, i32) -> i32)(a, b),
            a * b
        );
    }

    unsafe {
        replace_stub.unhook().expect("failed to unhook func");
        hook_stub.unhook().expect("failed to unhook func");
    }

    for (a, b) in [(0, 0), (2, 3), (-7, 5), (-11, -13)] {
        assert_eq!(
            hint::black_box(replace_target as extern "C" fn(i32, i32) -> i32)(a, b),
            a + b
        );
        assert_eq!(
            hint::black_box(hook_target as extern "C" fn(i32, i32) -> i32)(a, b),
            a + b
        );
    }
}

#[test]
fn drop_keeps_hook() {
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

fn patch_target() -> ExecutableBuffer {
    let mut ops = Assembler::new().unwrap();
    for _ in 0..8 {
        ops.extend(&0xd503201fu32.to_le_bytes()); // NOP
    }
    ops.extend(&0xd65f03c0u32.to_le_bytes()); // RET
    ops.finalize().unwrap()
}

extern "C" fn unused_callback(_: *mut c_long) {}

#[test]
fn conflicts_across_install_methods() {
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

#[test]
fn concurrent_installs() {
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

#[test]
fn unhook_rejects_changed_patch() {
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

#[test]
fn rejected_instructions_do_not_reserve_target() {
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

#[test]
fn page_end_patch_does_not_touch_next_page() {
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

#[test]
#[allow(clippy::too_many_arguments)]
fn replace_preserves_stack_arguments() {
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

mod backtrace {
    use crate::{Wisp, orig_fn};
    use std::ffi::c_void;
    use std::fs::{self, File};
    use std::process::{self, Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::time::{Duration, Instant};
    use std::{env, hint, io, mem, ptr, thread};

    struct Capture {
        tid: AtomicI32,
        release: AtomicBool,
        original: usize,
    }

    type Probe = extern "C" fn(&Capture) -> usize;

    #[inline(never)]
    #[unsafe(no_mangle)]
    extern "C" fn wisp_backtrace_wait(capture: &Capture) -> usize {
        capture
            .tid
            .store(unsafe { libc::gettid() }, Ordering::Release);

        while !capture.release.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(10));
        }

        hint::black_box(1)
    }

    #[inline(never)]
    #[unsafe(no_mangle)]
    extern "C" fn wisp_backtrace_target(capture: &Capture) -> usize {
        let result = hint::black_box(wisp_backtrace_wait as Probe)(capture);
        // Keep a real frame even in release builds: no tail call to the next function.
        hint::black_box(result + 2)
    }

    #[inline(never)]
    #[unsafe(no_mangle)]
    extern "C" fn wisp_backtrace_saved(capture: &Capture) -> usize {
        let original = unsafe { mem::transmute::<usize, Probe>(capture.original) };
        let result = original(capture);
        hint::black_box(result + 4)
    }

    #[inline(never)]
    #[unsafe(no_mangle)]
    extern "C" fn wisp_backtrace_tls(capture: &Capture) -> usize {
        let original = unsafe { orig_fn!(extern "C" fn(&Capture) -> usize) };
        let result = original(capture);
        hint::black_box(result + 4)
    }

    #[inline(never)]
    #[unsafe(no_mangle)]
    extern "C" fn wisp_backtrace_caller(capture: &Capture) -> usize {
        let result = hint::black_box(wisp_backtrace_target as Probe)(capture);
        hint::black_box(result + 8)
    }

    fn collect() -> io::Result<String> {
        let path = env::current_exe()?.with_file_name(format!("backtrace-{}.txt", process::id()));
        let file = File::create_new(&path)?;
        let result = (|| {
            let mut command = if unsafe { libc::geteuid() } == 0 {
                Command::new("/system/bin/timeout")
            } else {
                let mut command = Command::new("/system/xbin/su");
                command.args(["0", "/system/bin/timeout"]);
                command
            };
            // Run timeout with the same credentials as debuggerd so it can kill it.
            let status = command
                .args([
                    "-k",
                    "1",
                    "10",
                    "/system/bin/debuggerd",
                    "-b",
                    &process::id().to_string(),
                ])
                .stdout(Stdio::from(file.try_clone()?))
                .stderr(Stdio::from(file))
                .status()?;
            let output = fs::read_to_string(&path)?;

            if status.success() {
                Ok(output)
            } else {
                Err(io::Error::other(format!(
                    "debuggerd failed or timed out ({status}); requires root and permission to read the test ELF\n{output}"
                )))
            }
        })();
        let _ = fs::remove_file(path);

        result
    }

    fn check(proxy: Option<Probe>, proxy_symbol: Option<&str>) {
        let mut original: *const c_void = ptr::null();
        let stub = proxy.map(|proxy| unsafe {
            Wisp::hook_fn(wisp_backtrace_target as _, proxy as _, Some(&mut original)).unwrap()
        });
        let capture = Capture {
            tid: AtomicI32::new(0),
            release: AtomicBool::new(false),
            original: original as usize,
        };
        let (output, result) = thread::scope(|scope| {
            let worker = scope.spawn(|| wisp_backtrace_caller(&capture));
            let start = Instant::now();

            while capture.tid.load(Ordering::Acquire) == 0
                && start.elapsed() < Duration::from_secs(5)
            {
                thread::sleep(Duration::from_millis(1));
            }

            let output = if capture.tid.load(Ordering::Acquire) == 0 {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "worker did not reach capture point",
                ))
            } else {
                collect()
            };

            capture.release.store(true, Ordering::Release);
            (output, worker.join())
        });

        if let Some(stub) = stub {
            unsafe { stub.unhook().unwrap() };
        }

        let output = output.expect("failed to collect Android backtrace");
        let tid = format!("sysTid={}", capture.tid.load(Ordering::Acquire));
        let mut lines = output.lines();

        println!("{output}");
        assert_eq!(result.unwrap(), if proxy.is_some() { 15 } else { 11 });
        assert!(
            lines.any(|line| line.split_whitespace().any(|part| part == tid)),
            "worker thread missing:\n{output}"
        );

        let frames: Vec<_> = lines
            .take_while(|line| !line.starts_with('"') && !line.starts_with("----- end"))
            .filter(|line| line.trim_start().starts_with('#'))
            .collect();
        let expected = [
            Some("wisp_backtrace_wait"),
            Some("wisp_backtrace_target"),
            proxy_symbol,
            Some("wisp_backtrace_caller"),
        ];
        let mut remaining = frames.as_slice();

        for symbol in expected.into_iter().flatten() {
            let marker = format!("({symbol}+");
            let index = remaining.iter().position(|line| line.contains(&marker))
                .unwrap_or_else(|| panic!("missing or out-of-order frame {symbol}; debuggerd must be able to read the test ELF:\n{output}"));
            remaining = &remaining[index + 1..];
        }
    }

    #[test]
    #[ignore = "requires root debuggerd and permission to read the test ELF; does not change SELinux"]
    fn baseline() {
        check(None, None);
    }

    #[test]
    #[ignore = "requires root debuggerd and permission to read the test ELF; does not change SELinux"]
    fn saved_original() {
        check(Some(wisp_backtrace_saved), Some("wisp_backtrace_saved"));
    }

    #[test]
    #[ignore = "requires root debuggerd and permission to read the test ELF; does not change SELinux"]
    fn tls_original() {
        check(Some(wisp_backtrace_tls), Some("wisp_backtrace_tls"));
    }
}
