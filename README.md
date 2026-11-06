# Wisp

![wisp](https://socialify.git.ci/Mufanc/wisp/image?custom_description=A+lightweight+Rust+library+for+inline+hooking+on+Android&custom_language=Rust&description=1&font=Inter&forks=1&language=1&name=1&owner=1&pattern=Plus&stargazers=1&theme=Light)

Wisp is a lightweight Rust inline hooking library for Android ARM64 (`aarch64-linux-android`). It replaces or intercepts function calls by patching executable code at runtime.

The project is under development, and the public API may change in future releases. See the [safety requirements and limitations](docs/SAFETY.md) before use.

## Features

- Replace functions with proxy implementations.
- Hook functions while retaining access to the original implementation.
- Retrieve the original function dynamically with `orig_fn!()`.
- Intercept function entries and modify saved argument registers through a callback.
- Install single-instruction entry patches through nearby branch islands.
- Relocate supported ARM64 PC-relative instructions into original trampolines.
- Detect overlapping hooks and serialize management operations within one Wisp instance.
- Synchronize the instruction cache after code changes.

## Documentation

- [Installation, usage and API](docs/API.md)
- [Safety requirements, limitations and resource lifetimes](docs/SAFETY.md)
