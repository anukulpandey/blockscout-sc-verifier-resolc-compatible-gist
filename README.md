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

Need to install the `resolc` binary locally too. So downloaded it from [here](https://github.com/paritytech/revive/releases)

and added it to path after installation

```
sudo mv /Users/anukul/Desktop/llvm-rust/resolc /usr/local/bin/resolc
sudo chmod +x /usr/local/bin/resolc
```

got this error next, i.e it expects `solc` as well.

```

cargo run
   Compiling llvm-sys v181.2.0
   Compiling lld-sys v0.1.0
   Compiling revive-builtins v0.1.0
   Compiling revive-runtime-api v0.2.0
   Compiling revive-stdlib v0.1.1
   Compiling inkwell v0.6.0
   Compiling revive-linker v0.1.0
   Compiling revive-llvm-context v0.3.0
   Compiling revive-yul v0.2.1
   Compiling resolc v0.3.0
   Compiling solidity_compiler_cli v0.1.0 (/Users/anukul/Desktop/llvm-rust/solidity_compiler_cli)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.24s
     Running `target/debug/solidity_compiler_cli`

thread 'main' (501366) panicked at /Users/anukul/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/resolc-0.3.0/src/test_utils.rs:46:9:
The `solc` executable not found in ${PATH}
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
anukul@Mac solidity_compiler_cli %

```

so installed it from [here](https://docs.soliditylang.org/en/latest/installing-solidity.html)

by running the following

```
brew tap ethereum/ethereum
brew install solidity
```
