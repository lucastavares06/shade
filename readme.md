# shade 🚀

a small windows tool for unloading and hiding dll modules from toolhelp32 snapshots - built to explore rust and the win32 api.

## what it does

calls `FreeLibrary` repeatedly until the module's reference count reaches zero, removing it from the process module list. before unloading, it snapshots the module's memory and remaps it at the original base address.

the result: the module disappears from `CreateToolhelp32Snapshot`, `EnumProcessModules`, and any scanner that relies on toolhelp32 - but the code is still alive in memory at the same address. existing hooks and callbacks keep pointing to valid code and won't crash.

> the module is not gone. it's just invisible. the memory is still there and can be recovered trivially by scanning the process address space.

## options

| option | effect |
|---|---|
| keep frozen stub | snapshots memory before unload and remaps it - keeps hooks alive |
| neutralize DllMain | patches the entry point to prevent callbacks during unload |

## limitations

- x86 only - the injected shellcode uses x86 calling conventions

## building

```
cargo build --release
```

requires the msvc toolchain: `x86_64-pc-windows-msvc` or `i686-pc-windows-msvc`.

## purpose

just for fun. messing around with rust and win apis in a context i actually enjoy.
