# Safety requirements and limitations

[Project overview](../README.md) · [Installation and API](API.md)

Wisp is experimental and is not ready for production use. Its unsafe APIs require the caller to establish the conditions below. Runtime checks do not prove that a hook is safe.

## Function entries and calling conventions

- Pass valid, four-byte-aligned ARM64 function entries with sufficient readable executable memory. Wisp supports entry hooks; arbitrary instruction addresses are outside the API contract.
- Target and proxy signatures and ABIs must match. Use the base AAPCS64 calling convention; do not assume support for SVE/SME state or other calling conventions.
- Treat x17 as available scratch for entry jumps, relocation and trampoline resumption. Targets must not depend on its value surviving those points. Other GPRs and SP/LR are restored before the hook proxy starts.
- Hooking and interception explicitly protect GPRs, rather than SIMD or status registers. The current TLS path has been checked on an API 36 ARM64 emulator to leave SIMD unchanged; this is an implementation assumption that must be checked with other libc versions or toolchains.
- Intercept callbacks must respect the actual argument layout and preserve the validity of any modified arguments.

`hook_fn` and `intercept_fn` currently reject a PC-relative first instruction, including address generation, literal loads and immediate branches. Instruction relocation is not implemented. `replace_fn` does not execute the displaced instruction and does not apply that rejection.

`orig_fn!` uses one per-thread slot. If needed, read it once before entering any other hook and retain the pointer locally. Nested calls can then use the same slot independently. The macro and installer must use the same Wisp instance. Skipping the macro requires no cleanup; the next hook entry overwrites the slot.

Do not hook routines that Wisp itself needs while installing, removing or dispatching hooks, such as its TLS, allocator or memory-management dependencies. Re-entering Wisp through those dependencies can recurse or deadlock. This restriction concerns Wisp's own dependency paths, not every target that happens to call a library function.

## Thread synchronization and independent instances

The caller must ensure that no thread is executing the affected target, proxy, callback or trampoline during installation or removal. Before releasing an original trampoline, also ensure that no execution or retained pointer can use it afterward. The management mutex does not suspend execution threads or wait for active calls to finish.

One linked Wisp instance serializes management operations and maintains its own reservations. Separate statically linked copies do not discover or coordinate with one another. Callers must coordinate patches, page permissions, reservations, island use and module lifetimes across instances. An external shared API backed by one Wisp instance can centralize that coordination.

Keep Wisp, target and proxy/callback modules loaded while execution or usable references depend on them. Coordinate module loading and unloading with hook management. See [`release_module`](API.md#handles-and-module-cleanup) for the required cleanup order after unloading a target module.

## Memory permissions and islands

Each target entry is patched with one aligned four-byte branch to a nearby island. Installation requires reachable executable space and can fail when none is available. The allocator uses the target module's RX segment tails, existing shared spaces and nearby anonymous mappings. ELF gap spaces are restricted to targets in their owning module; neighboring modules' gaps are not borrowed.

The process needs permission to write and execute the affected mappings. Wisp uses `mprotect` to make code pages RWX, including the applicable Android SELinux `execmem` permission for private code mappings. Running as UID 0 alone does not bypass SELinux policy. There is no `/proc/self/mem` fallback.

Target writes restore the page's recorded R/W/X flags. BTI is removed from modified pages and is not restored. Registering an RX tail as island space makes its entire page, including any preceding live code, remain RWX. Anonymous island pages also remain RWX. Unhooking does not restore these pages' original protections.

## Runtime checks

| Check | Result |
| --- | --- |
| Null or unaligned target | `InvalidAddress` |
| Target patch overlaps a reservation in this instance | `Conflict` |
| Unsupported PC-relative instruction for hooking/interception | `NotSupported` |
| No suitable reachable island space | `Island` |
| Unhook reservation missing or installed patch bytes changed | `PatchMismatch` |
| Module cleanup finds an allocated private island | `ModuleInUse` |

Wisp also reports assembly, memory-operation and other I/O errors. It does not validate that an aligned address is a real function, that signatures match, that x17 is available, that argument modifications are valid, or that threads and modules have been coordinated. Those remain caller obligations; violating unsafe preconditions is outside the supported contract and can cause undefined behavior.

## Failure handling and resource lifetimes

Before unhooking, Wisp checks the reservation and compares the complete installed patch against the bytes retained in the non-cloneable `Stub`. A mismatch returns an error without overwriting the entry.

Successful unhook restores the saved instruction, synchronizes the instruction cache, releases the reservation and trampoline buffers, and immediately returns the island allocation for reuse. Island backing pages and unused allocator capacity remain retained. There is no complete process-state cleanup API yet.

Dropping a stub without unhooking retains its resources. Failed unhooks also retain the reservation, island and executable buffers. A failed installation releases them only when the target entry still equals the original bytes; a partial or complete patch left behind retains them. Failure does not guarantee that the target remains callable. Neither failed installation nor the consuming `unhook` API returns a recovery handle.

The TLS key is initialized once per Wisp instance and retained across unhooking. There are no per-thread heap contexts or TLS destructors. Key creation failure is reported through `Io`; failure to write or clear TLS during execution aborts the process, because the target's arbitrary return type provides no error-return channel.

## Validation boundaries

Current validation includes Android ARM64 emulator tests. Physical-device SELinux/BTI behavior, signal re-entry and exception unwinding have not been validated. Serialized management does not provide safe concurrent patching while target code executes. Stacking multiple hooks on the same target is not supported; unhooking and subsequently installing a new hook is supported.
