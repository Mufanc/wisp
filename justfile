#!/usr/bin/env just --justfile

TARGET_SDK := "35"

# https://developer.android.com/ndk/guides/other_build_systems#overview
HOST_TAG := (if os() == "macos" { "darwin" } else { os() }) + "-x86_64"

export CC := env("ANDROID_NDK") / "toolchains/llvm/prebuilt" / HOST_TAG / "bin" / ("aarch64-linux-android" + TARGET_SDK + "-clang")

test *args:
    cargo build --locked --release -p wisp-test-runner \
        --target aarch64-linux-android \
        --config target.aarch64-linux-android.linker=\"{{CC}}\"
    cargo test --locked \
        --target aarch64-linux-android \
        --config target.aarch64-linux-android.linker=\"{{CC}}\" {{args}}

clean:
    cargo clean
