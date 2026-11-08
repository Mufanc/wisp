# Installation and API

[Project overview](../README.md) · [Safety requirements](SAFETY.md)

Wisp targets Android ARM64 (`aarch64-linux-android`). The examples assume that the caller has established the [required permissions, synchronization and module lifetimes](SAFETY.md).

## Installation

```toml
[dependencies]
wisp = { git = "https://github.com/Mufanc/wisp" }
```

## Function replacement

`replace_fn` redirects the target entry to a proxy. It does not provide an original function pointer.

```rust
use wisp::{Wisp, WispResult};

#[inline(never)]
extern "C" fn target(a: i64, b: i64) -> i64 {
    a + b
}

extern "C" fn proxy(a: i64, b: i64) -> i64 {
    a * b
}

fn main() -> WispResult<()> {
    unsafe {
        let stub = Wisp::replace_fn(target as _, proxy as _)?;
        assert_eq!(std::hint::black_box(target)(2, 3), 6);
        stub.unhook()?;
    }

    Ok(())
}
```

## Function hooking

`hook_fn` lets the proxy call the original implementation. Use `orig_fn!` to obtain the pointer for the current invocation without a global variable. The displaced instruction is relocated within the [supported instruction set](SAFETY.md#function-entries-and-calling-conventions).

```rust
use wisp::{Wisp, WispResult, orig_fn};

#[inline(never)]
extern "C" fn target(a: i64, b: i64) -> i64 {
    a + b
}

extern "C" fn proxy(a: i64, b: i64) -> i64 {
    let original = unsafe { orig_fn!(unsafe extern "C" fn(i64, i64) -> i64) };
    let result = unsafe { original(a, b) };

    result * 2
}

fn main() -> WispResult<()> {
    unsafe {
        let stub = Wisp::hook_fn(target as _, proxy as _, None)?;
        assert_eq!(std::hint::black_box(target)(2, 3), 10);
        stub.unhook()?;
    }

    Ok(())
}
```

The optional third argument, `Some(&mut pointer)`, stores the original address in caller-owned storage. The caller manages its publication and lifetime. Passing `None` skips that output; `orig_fn!` remains available.

### `orig_fn!`

- `unsafe { orig_fn!() }` returns `*const c_void`.
- `unsafe { orig_fn!(FunctionPointerType) }` returns a callable pointer of the supplied type, which must match the target's signature and ABI.

If used, obtain the pointer once at the beginning of the proxy, before any call that could enter another hook. Each hook entry writes its original address into a single per-thread TLS slot; the macro reads and clears it. Keep the returned pointer in a local variable for later or repeated calls, including after nested hooks.

The macro must come from the same linked Wisp instance that installed the hook. Proxies that do not need the address from TLS may omit it. A retained original pointer must not be used after unhooking.

## Function interception

`intercept_fn` calls a callback before executing the original implementation. The callback receives a pointer to the saved x0–x7 register values.

```rust
use libc::c_long;
use wisp::{Wisp, WispResult};

#[inline(never)]
extern "C" fn target(a: i64, b: i64) -> i64 {
    a + b
}

extern "C" fn callback(args: *mut c_long) {
    unsafe {
        *args = 100;
        *args.add(1) = 200;
    }
}

fn main() -> WispResult<()> {
    unsafe {
        let stub = Wisp::intercept_fn(target as _, callback)?;
        assert_eq!(std::hint::black_box(target)(1, 2), 300);
        stub.unhook()?;
    }

    Ok(())
}
```

Map these physical register slots to arguments using the target ABI. Floating-point, aggregate and stack-passed arguments follow their ABI layouts. The callback must establish the layout before reading or changing values. Add `libc` as a direct dependency when using its types in application code.

## Handles and module cleanup

| API | Behavior |
| --- | --- |
| `Wisp::replace_fn(target, proxy)` | Replaces a function and returns a `Stub`. |
| `Wisp::hook_fn(target, proxy, backup_orig)` | Installs a proxy with access to the original implementation and returns a `Stub`. |
| `Wisp::intercept_fn(target, callback)` | Installs an entry callback and returns a `Stub`. |
| `Stub::target(&self)` | Returns the target address. |
| `Stub::unhook(self)` | Consumes the handle, restores the saved instruction and releases its trampoline buffers and island allocation on success. |
| `Wisp::release_module(address)` | After a module has been unloaded, removes its cached private island spaces using an address saved from that module. |

Installation and cleanup methods are unsafe and return `WispResult<T>` (`Result<T, WispError>`). `Stub::target` is a safe accessor.

Dropping a `Stub` leaves the hook, reservation and executable buffers installed. Explicitly call `unhook` when restoration is needed. Successful unhook allows immediate island reuse; backing island pages remain allocated. See [failure handling and resource lifetimes](SAFETY.md#failure-handling-and-resource-lifetimes).

For `release_module`, first unhook all related hooks, finish all related execution and references, then unload the module. Only afterward call `release_module` with a saved address from one of its loaded segments. Prevent reuse of its address ranges until cleanup finishes. The method removes Wisp’s cached records; it does not unload the module or restore page permissions. It returns `ModuleInUse` if any private island remains allocated; an unregistered module or repeated cleanup is a no-op. Shared island pages are retained.

## Testing

The test recipe requires `just`, an Android NDK with the API 35 ARM64 compiler, the Rust Android ARM64 target, and `adb` connected to a device or emulator. Set `ANDROID_NDK` to the NDK directory, then run:

```bash
just test
just test --release
just test relocate::tests:: -- --test-threads=1
```

The [runner](../.cargo/bin/remote-test-runner) uploads the driver and test binary once into a temporary device directory, then removes the directory when the run finishes. Set `ANDROID_SERIAL` to select a device.

The device driver discovers existing `#[test]` cases and runs each in a fresh process. Up to four test processes run concurrently; `--test-threads` can reduce this number but cannot exceed four. Failures and crashes are collected without stopping the remaining tests. Each process has a 30-second timeout, configurable through `WISP_TEST_TIMEOUT` (positive integer seconds). Test output is included on failure; `--nocapture` or `--show-output` also shows successful output after each process exits.

Name filtering, `--exact`, `--skip`, `--list`, `--ignored`, and `--include-ignored` are handled by the driver.

Run the driver’s own process-isolation and failure-handling checks on the host with `cargo test -p wisp-test-runner`. These compile a standalone fixture with `rustc` and deliberately exercise panic, abort, and timeout cases.

The debuggerd backtrace tests are ignored by default. Run them explicitly with `just test tests::backtrace:: -- --ignored --test-threads=1` (add `--release` before the filter for release builds). They collect the worker thread's stack and assert the order of the target, proxy, and caller frames. Collection requires root, either directly or through Android's `/system/xbin/su 0`, and permission for crash_dump to read the test ELF. On the current emulator, the `/data/local/tmp` deployment requires an externally prepared permissive SELinux environment. The tests never change SELinux; missing permissions, missing frames, and collection timeouts fail the test. This checks debuggerd backtraces inside the original function, not exception unwinding or sampling inside a trampoline.
