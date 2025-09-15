# blockscout-rs/sc-verifier compatible with resolc compiler

```
[NOTE]

revive depends on a custom build of LLVM v18.1.8 with the RISC-V embedded target, including the compiler-rt builtins. You can either download a build from our releases (recommended for older hardware) or build it from source.
```
so downloaded it from [here](https://github.com/paritytech/revive/releases?q=LLVM+binaries+release&expanded=true)

After downloading, installed it using

```
xattr -rc /Users/anukul/Desktop/llvm-rust/target-llvm/gnu/target-final/bin/*
chmod +x /Users/anukul/Desktop/llvm-rust/target-llvm/gnu/target-final/bin/*
export LLVM_SYS_181_PREFIX=/Users/anukul/Desktop/llvm-rust/target-llvm/gnu/target-final
export PATH="$LLVM_SYS_181_PREFIX/bin:$PATH"
```

In a sample rust app added this

```
...

[dependencies]
resolc = "0.3"

...

```

then for installing it, ran

```
cargo run
```
