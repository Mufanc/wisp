# Wisp

![wisp](https://socialify.git.ci/Mufanc/wisp/image?custom_description=A+lightweight+Rust+library+for+inline+hooking+on+Android&custom_language=Rust&description=1&font=Inter&forks=1&language=1&name=1&owner=1&pattern=Plus&stargazers=1&theme=Light)

## Overview

Wisp provides runtime function hooking capabilities for ARM64 platforms, primarily designed for Android (aarch64-linux-android). It allows you to replace or intercept function calls at runtime by dynamically modifying executable code.

> **Warning**: This library is still under development and cannot handle cases where instructions at the beginning of the target function contain PC-relative addressing instructions like `adrp`. Do not use in production environments.

## Features

- **Function Replacement**: Replace target functions entirely with proxy implementations
- **Function Hooking**: Intercept function calls while preserving access to original implementation
- **Dynamic Original Function**: Retrieve original function pointer dynamically via `orig_fn!()` macro
- - **Function Interception**: Modify function arguments at runtime via a callback before the original function executes
- **Instruction Cache Synchronization**: Ensures cache coherency after code modifications

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
wisp = { git = "https://github.com/Mufanc/wisp" }
```

## Usage

### Function Replacement

Replace a target function entirely with a proxy function:

```rust
use wisp::Wisp;

extern "C" fn target_fn(a: i32, b: i32) -> i32 {
    a + b
}

extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
    a * b
}

unsafe {
    let stub = Wisp::replace_fn(target_fn as _, proxy_fn as _)
        .expect("failed to replace function");
    
    // target_fn now executes proxy_fn's code
    assert_eq!(target_fn(2, 3), 6); // 2 * 3

    // Save the stub and explicitly unhook when restoration is needed.
    stub.unhook().expect("failed to unhook function");
    assert_eq!(target_fn(2, 3), 5);
}
```

Dropping a stub leaves the hook and its executable buffers installed until process exit. Call `Stub::unhook` explicitly before dropping it to restore the original function.

### Function Hooking

Hook a function while maintaining access to the original implementation:

```rust
use wisp::Wisp;
use std::ffi::c_void;

static mut ORIG_FN: *const c_void = std::ptr::null();

extern "C" fn target_fn(a: i32, b: i32) -> i32 {
    a + b
}

extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
    // Call original function
    let result = unsafe {
        std::mem::transmute::<*const c_void, fn(i32, i32) -> i32>(ORIG_FN)(a, b)
    };
    
    // Modify behavior
    result * 2
}

unsafe {
    let _stub = Wisp::hook_fn(target_fn as _, proxy_fn as _, Some(&mut ORIG_FN))
        .expect("failed to hook function");
    
    assert_eq!(target_fn(2, 3), 10); // (2 + 3) * 2
}
```

### Dynamic Original Function

Use `orig_fn!()` macro to dynamically retrieve the original function without static variables:

```rust
use wisp::{Wisp, orig_fn};
use std::ffi::c_void;
use std::mem;

extern "C" fn target_fn(a: i32, b: i32) -> i32 {
    a + b
}

extern "C" fn proxy_fn(a: i32, b: i32) -> i32 {
    let orig_fn = orig_fn!();
    
    // Call original function
    let result = unsafe {
        mem::transmute::<*const c_void, fn(i32, i32) -> i32>(orig_fn)(a, b)
    };
    
    // Modify behavior
    result * 2
}

unsafe {
    let _stub = Wisp::hook_fn(target_fn as _, proxy_fn as _, None)
        .expect("failed to hook function");
    
    assert_eq!(target_fn(2, 3), 10); // (2 + 3) * 2
}
```

### Function Interception

Intercept a function to modify its arguments at runtime via a callback before the original function executes:

```rust
use wisp::Wisp;
use libc::c_long;

extern "C" fn target_fn(a: u32, b: u32) -> u32 {
    a + b
}

extern "C" fn callback_fn(args: *mut c_long) {
    unsafe {
        // args points to saved registers x0-x7 on the stack
        // Modify x0 (first argument)
        *args = 100;
        // Modify x1 (second argument)
        *args.add(1) = 200;
    }
}

unsafe {
    let _stub = Wisp::intercept_fn(target_fn as _, callback_fn)
        .expect("failed to intercept function");

    // target_fn is called with modified arguments (100, 200) regardless of input
    assert_eq!(target_fn(1, 2), 300);
}
```

The callback receives a pointer to the saved argument registers (x0-x7) on the stack, allowing you to read or modify any of the first 8 arguments before the original function executes.

### Custom Unhook Behavior

Implement custom unhooking logic with the `Unhooker` trait:

```rust
use wisp::{CustomWisp, UnhookContext, Unhooker, WispResult};

struct MadviseUnhooker;

unsafe impl Unhooker for MadviseUnhooker {
    fn unhook(context: UnhookContext<'_>) -> WispResult<()> {
        // Pseudocode:
        // let pages = page_range(context.target(), context.backup_insn().len());
        // madvise(pages, MADV_DONTNEED);
        // touch_pages(pages);
        todo!()
    }
}

type MadviseWisp = CustomWisp<MadviseUnhooker>;
```

## API

### Core Types

- `Wisp`: Main type alias for `CustomWisp<SimpleUnhooker>`
- `CustomWisp<U>`: Generic hooking interface with custom unhooker
- `Stub<U>`: Handle used to explicitly unhook a function
- `UnhookContext`: Read-only target information passed to an unhooker
- `Unhooker`: Unsafe extension point for custom unhook behavior
- `SimpleUnhooker`: Default unhooker implementation

### Methods

#### `Wisp::replace_fn`

```rust
pub unsafe fn replace_fn(
    target_fn: *const c_void,
    proxy_fn: *const c_void,
) -> WispResult<Stub<U>>
```

Replaces the target function with a proxy function.

#### `Wisp::hook_fn`

```rust
pub unsafe fn hook_fn(
    target_fn: *const c_void,
    proxy_fn: *const c_void,
    backup_orig: Option<&mut *const c_void>,
) -> WispResult<Stub<U>>
```

Hooks the target function while preserving access to the original implementation. Pass `Some(&mut ptr)` to store the original function pointer, or `None` to skip storing.

#### `Wisp::intercept_fn`

```rust
pub unsafe fn intercept_fn(
    target_fn: *const c_void,
    callback_fn: extern "C" fn(*mut c_long),
) -> WispResult<Stub<U>>
```

Intercepts the target function, invoking the callback with a mutable pointer to the saved arguments on the stack before executing the original function. The callback can read or modify the arguments.

#### `Stub::unhook`

```rust
pub unsafe fn unhook(self) -> WispResult<()>
```

Restores the target function and releases its executable buffers. Dropping the stub without calling this method leaves the hook installed.

#### `orig_fn!()`

Macro to dynamically retrieve the original function pointer within a proxy function. **Must be called at the beginning of the proxy function**.

## Limitations

- **Recursive functions**: Hooking functions that recursively call themselves is not supported
- **Multiple hooks**: Attaching multiple hooks to a single function is not supported
- **Minimum instruction length**: Target functions must have at least 4 ARM64 instructions (16 bytes)
- **Concurrent operations**: Simultaneous hook/unhook operations on the same function from multiple threads result in undefined behavior
- **Internal library calls**: Behavior is undefined when hooking functions that internally use library functions like `open`, `mmap`, etc.

## Safety

All hooking operations are inherently unsafe and require careful consideration:

- Target and proxy functions must be valid pointers to executable code
- Target functions must not be executed by other threads during patching to avoid race conditions
- Proper synchronization is the caller's responsibility
- Hooking functions whose first 4 instructions contain PC-relative addressing instructions (e.g., `adrp`) is **not yet supported**

## Testing

Run tests on Android ARM64 target:

```bash
just
```

This requires:
- Android NDK installed
- `ANDROID_NDK` environment variable set
- `cargo-nextest` installed

## Platform Support

Currently supports:
- **Architecture**: ARM64/AArch64
- **Target**: aarch64-linux-android
