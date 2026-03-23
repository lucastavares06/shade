# shade

A small Windows tool for unloading and hiding DLL modules from Toolhelp32 snapshots - built to explore Rust and the Win32 API.

## What It Does

Calls `FreeLibrary` repeatedly via injected shellcode until the module's reference count reaches zero, removing it from the process module list. Before unloading, it snapshots the module's memory regions (including original page protections) and remaps them at the original base address as a frozen stub.

The result: the module disappears from `CreateToolhelp32Snapshot`, `EnumProcessModules`, and any scanner that relies on Toolhelp32 - but the code is still alive in memory at the same address. Existing hooks and callbacks keep pointing to valid code and won't crash.

> The module is not gone. It's just invisible. The memory is still there and can be recovered trivially by scanning the process address space.

## Options

| Option | Effect |
|---|---|
| Keep Frozen Stub | Snapshots memory before unload and remaps it with original page protections - keeps hooks alive |
| Neutralize DllMain | Patches the entry point with a RAII guard to prevent callbacks during unload, auto-restores on failure |

## Architecture

- **Structured logging** - `UnloadLogger` trait with level-based output (`Info`, `Success`, `Warning`, `Error`), decoupled from business logic
- **RAII entry point guard** - `EntryPointGuard` auto-restores patched bytes on drop, preventing corrupted DllMain on early returns or panics
- **Configurable retry strategy** - `Fixed`, `ExponentialBackoff`, or deadline-based `UntilTimeout` for the FreeLibrary loop
- **Remote thread timeout** - configurable `WaitForSingleObject` timeout instead of `INFINITE`, prevents host process hang on DllMain deadlocks
- **PE header validation** - verifies MZ/NT signatures and offset ranges before patching
- **Post-unload verification** - confirms address space is `MEM_FREE` via `VirtualQueryEx` before attempting stub remap
- **Structured result** - `UnloadResult` with explicit fields (`module_unloaded`, `stub_remapped`, `entry_point_restored`, `freelibrary_calls`) instead of string parsing

## Limitations

- x86 only - the injected shellcode uses x86 calling conventions

## Building

```
cargo build --release
```

Requires the MSVC toolchain: `x86_64-pc-windows-msvc` or `i686-pc-windows-msvc`.

## Usage

1. Enter the target process name (e.g. `gta_sa.exe`)
2. Enter the module to hide (e.g. `crashes.asi`)
3. Click **HIDE MODULE**

## Purpose

Just for fun. Messing around with Rust and Win32 APIs in a context I actually enjoy. 🚀
