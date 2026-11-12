# wboxUnlocker

Runtime unlocker for **WorldBox 0.51.4** (Unity 2022.3.62f3, arm64-v8a).

The mod no longer patches a fixed list of AOBs and no longer writes a precomputed
save file. It resolves IL2CPP at runtime, hooks the shared entitlement helper,
and installs named bool hooks for premium/progress checks.

## How it works

1. Waits for `libil2cpp.so` to appear in the loaded-module list, then resolves
   the obfuscated IL2CPP API exports from its in-memory ELF `.dynsym` by name.
2. Decodes each exported API wrapper to the internal implementation it calls
   (first unconditional `b`, or the last `b`/`bl` before the first `ret`).
3. Finds the shared entitlement helper in the executable segments by its
   entry prologue signature and hooks it to return `true`. This replaces the
   22 old `mov w0,#1` patches and covers all 44 helper call sites.
4. Waits for the IL2CPP assembly vector to become stable, obtains the domain,
   and attaches the mod thread with `il2cpp_thread_attach`.
5. Enumerates `InAppManager`, `GameProgress`, and `GameProgressData` at runtime.
   Every field and method is written to
   `/sdcard/Android/data/<package>/files/mods/log.txt` (and logcat, tag
   `WBoxHack`).
6. Installs a generic true-return ShadowHook on bool methods whose names look
   like premium/progress checks. Method names are encrypted in
   `global-metadata.dat`, so the runtime log is the authoritative list of names
   for future refinements.

There is no `save_data.h` and no save-file injection.

## ShadowHook

ShadowHook 2.0.1 is vendored in `third_party/shadowhook` and compiled directly
into `libaeeL.so` as a static library. `libshadowhook_nothing.so` is not built or
packaged.

Only address-based hooks on the already-loaded `libil2cpp.so` are used, so
`sh_linker_init()` is patched to skip:

- hooking the linker's `soinfo::call_constructors` / `call_destructors`;
- the `dlopen("libshadowhook_nothing.so")` soinfo memory scan.

The patch is documented inline in `third_party/shadowhook/sh_linker.c`.

## Build

Requires the Android NDK (CMake toolchain). From the project root:

```sh
cmake -S . -B build \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_LATEST_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-23 \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --target aeeL --parallel
```

The artifact is `build/libaeeL.so`. CI uses the same commands and uploads
`output/lib/arm64-v8a/libaeeL.so` as the `mod_aeeL` artifact.

## Notes

- Target package: `com.mkarpenko.worldbox`.
- Runtime logs are written to the app's external files directory; inspect
  `mods/log.txt` after launching the game.
- No root, `su`, ADB, or on-device memory inspection is required.
