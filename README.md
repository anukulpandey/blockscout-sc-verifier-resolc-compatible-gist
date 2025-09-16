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

Verified it using

```
solc --version
```

got this

```
anukul@Mac ~ % solc --version            
solc, the solidity compiler commandline interface
Version: 0.8.30+commit.73712a01.Darwin.appleclang
```

The `main.rs` looks like this rn

```
use resolc::test_utils::compile_evm_deploy_code;

fn main() {
    let source_code = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

contract Flipper {
    bool private value;

    constructor(bool initialValue) {
        value = initialValue;
    }

    function flip() public {
        value = !value;
    }

    function get() public view returns (bool) {
        return value;
    }
}
"#;

    // Compile EVM deployable bytecode
    let bytecode = compile_evm_deploy_code("Flipper", source_code,false);

    println!("Compiled Flipper contract bytecode (hex): {}", hex::encode(bytecode));
}

```

the output after running it is

```
anukul@Mac solidity_compiler_cli % cargo run                                                                              
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.26s
     Running `target/debug/solidity_compiler_cli`
Compiled Flipper contract bytecode (hex): 608060405234610030575b61001a6100156100e9565b610156565b610022610035565b6101e761016382396101e790f35b61003b565b60405190565b5f80fd5b601f801991011690565b634e487b7160e01b5f52604160045260245ffd5b906100679061003f565b810190811060018060401b03821117610080575b604052565b610049565b90610098610091610035565b928361005d565b565b5f80fd5b151590565b6100ac8161009e565b9014156100b6575b565b5f80fd5b905051906100c7826100a3565b565b906020828203126100e4575b6100e1915f90016100ba565b90565b61009a565b61010761034a803803806100fc81610085565b9283398101906100c9565b90565b5f1b90565b9061011b60ff9161010a565b91811990169116901790565b6101309061009e565b90565b90565b9061014b61014661015292610127565b610133565b825461010f565b9055565b610160905f610136565b56fe60806040526004361015610013575b6100fe565b61001d5f35610043565b80636d4ce63c1461003e575b63cde4efa914610039575b61000e565b6100ca565b61008e565b60e01c90565b60405190565b5f80fd5b5f80fd5b5f910312610062575b565b610053565b151590565b61007590610067565b9052565b919061008c905f6020850194019061006c565b565b346100bf575b61009f366004610057565b6100bb6100aa610133565b6100b2610049565b91829182610079565b0390f35b61004f565b5f900190565b346100f9575b6100db366004610057565b6100e3610194565b6100eb610049565b806100f5816100c4565b0390f35b61004f565b5f80fd5b5f90565b5f1c90565b60ff901690565b61011e61012391610106565b61010b565b90565b6101309054610112565b90565b61013b610102565b506101455f610126565b90565b5f1b90565b9061015960ff91610148565b91811990169116901790565b61016e90610067565b90565b90565b9061018961018461019092610165565b610171565b825461014d565b9055565b6101af6101a96101a35f610126565b15610067565b5f610174565b56fea264697066735822122037d2ff399ca02d3ee3eed1467dea1d7d11007298b808a2934a55579b7326804964736f6c634300081e0033
```

which is correct :))

Now going through `@blockscout-rs/smart-contract-verifier` to see what functions does it call on `solc` for verification of contracts and compilation.

Let's start with `standard_json` verification, this is the code in `@blockscout-rs/smart-contract-verifier`.

```
pub async fn verify(
    compilers: &EvmCompilersPool<SolcCompiler>,
    request: VerificationRequest,
) -> Result<VerificationResult, Error> {
    println!(
        "[verify] Starting verification for contract: {:?}, compiler_version: {:?}",
        request.contract, request.compiler_version
    );

    let to_verify = vec![request.contract];

    let results = verify::compile_and_verify(
        to_verify,
        compilers,
        &request.compiler_version,
        request.content,
    )
    .await?;

    let result = results
        .into_iter()
        .next()
        .expect("we sent exactly one contract to verify");

    println!("[verify] Verification result: {:?}", result);

    Ok(result)
}
```

this compile_and_verify looks like

```
pub async fn compile_and_verify<C: EvmCompiler>(
    to_verify: Vec<OnChainContract>,
    compilers: &EvmCompilersPool<C>,
    compiler_version: &DetailedVersion,
    compiler_input: C::CompilerInput,
) -> Result<Vec<VerificationResult>, Error> {
    let compilation_result =
        compilation::compile(compilers, compiler_version, compiler_input).await?;

    let mut verification_results = vec![];
    for contract in to_verify {
        verification_results.push(verify_on_chain_contract(contract, &compilation_result)?);
    }

    Ok(verification_results)
}
```

think I should just change the `compilation_result` here, let's see what `compile` does:

```

pub async fn compile<C: EvmCompiler>(
    compilers: &EvmCompilersPool<C>,
    compiler_version: &DetailedVersion,
    mut compiler_input: C::CompilerInput,
) -> Result<CompilationResult, Error> {
    let compiler_version = compilers.normalize_compiler_version(compiler_version)?;
    let compiler_path = compilers.fetch_compiler(&compiler_version).await?;

    compiler_input.normalize_output_selection(compiler_version.to_semver());
    let compiler_output = compilers
        .compile(&compiler_path, &compiler_version, &compiler_input)
        .await?;

    let modified_compiler_input = compiler_input.modified_copy();
    let modified_compiler_output = compilers
        .compile(&compiler_path, &compiler_version, &modified_compiler_input)
        .await?;

    let mut per_contract_artifacts = generate_per_contract_artifacts(compiler_output.output)?;
    let modified_per_contract_artifacts =
        generate_per_contract_artifacts(modified_compiler_output.output)?;

    let language = compiler_input.language();
    append_cbor_auxdata(
        language,
        &mut per_contract_artifacts,
        &modified_per_contract_artifacts,
    )?;

    Ok(CompilationResult {
        language,
        compiler_version: compiler_version.to_string(),
        compiler_settings: compiler_input.settings(),
        sources: compiler_input.sources(),
        artifacts: per_contract_artifacts,
    })
}
```

hmm it fetches the compiler version from here, not sure how these compiler versions are there and why not single compiler from solc like i have, maybe they have it from somewhere else, should check from where the compiler is coming

<img width="817" height="652" alt="Screenshot 2025-09-15 at 6 47 09 PM" src="https://github.com/user-attachments/assets/d69e25d1-829d-4cb5-bf6b-358a883d4de6" />

found it here, in the solidity_verification

```
impl SolidityVerifierService {
    pub async fn new(
        settings: SoliditySettings,
        compilers_threads_semaphore: Arc<Semaphore>,
    ) -> anyhow::Result<Self> {
        let solc_validator = Arc::new(SolcValidator::default());
        let fetcher = common::initialize_fetcher(
            settings.fetcher,
            settings.compilers_dir.clone(),
            settings.refresh_versions_schedule,
            Some(solc_validator),
        )
        .await
        .context("solidity fetcher initialization")?;

        let compilers: EvmCompilersPool<SolcCompiler> =
            EvmCompilersPool::new(fetcher, compilers_threads_semaphore);
        compilers.load_from_dir(&settings.compilers_dir).await;

        Ok(Self {
            compilers: Arc::new(compilers),
        })
    }
}

```

so compilers are downloaded from the fetcher service and stored in dir , from there it is fetched on the version which is required.
Let it be lets see what all it has inside the compiler and from where is this compiler coming, is it solc or some other lib

the file `smart-contract-verifier/src/verify/solc_compiler_cli.rs` is responsible for compilation etc.

This is the code responsible for compiling `solidity` (file name : `solc_compilers.rs` ):

```
use super::{evm_compilers, solc_compiler_cli, Error};
use crate::{DetailedVersion, Language, Version};
use anyhow::Context;
use async_trait::async_trait;
use foundry_compilers_new::{
    artifacts, artifacts::output_selection::OutputSelection, solc::SolcLanguage,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, sync::Arc};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct SolcInput(pub artifacts::SolcInput);

impl evm_compilers::CompilerInput for SolcInput {
    fn normalize_output_selection(&mut self, _version: &semver::Version) {
        self.0.settings.output_selection = OutputSelection::complete_output_selection();
    }

    fn modified_copy(&self) -> Self {
        let mut copy = self.clone();
        copy.0.sources.iter_mut().for_each(|(_file, source)| {
            let mut modified_content = source.content.as_ref().clone();
            modified_content.push(' ');
            source.content = Arc::new(modified_content);
        });
        copy
    }

    fn language(&self) -> Language {
        match self.0.language {
            SolcLanguage::Solidity => Language::Solidity,
            SolcLanguage::Yul => Language::Yul,
            // default value required because SolcLanguage enum is non_exhaustive
            _ => Language::Solidity,
        }
    }

    fn settings(&self) -> Value {
        serde_json::to_value(&self.0.settings).expect("failed to serialize settings")
    }

    fn sources(&self) -> BTreeMap<String, String> {
        let mut sources = BTreeMap::new();
        for (file_path, source) in self.0.sources.clone() {
            sources.insert(
                file_path.to_string_lossy().to_string(),
                source.content.as_ref().clone(),
            );
        }
        sources
    }
}

impl evm_compilers::CompilationError for artifacts::solc::Error {
    fn formatted_message(&self) -> String {
        self.formatted_message
            .clone()
            .unwrap_or(self.message.clone())
    }
}

#[derive(Debug, Default)]
pub struct SolcCompiler {}

#[async_trait]
impl evm_compilers::EvmCompiler for SolcCompiler {
    type CompilerInput = SolcInput;
    type CompilationError = artifacts::solc::Error;

    async fn compile(
        compiler_path: &Path,
        compiler_version: &DetailedVersion,
        input: &Self::CompilerInput,
    ) -> Result<Value, Error> {
        if compiler_version.to_semver() < &semver::Version::new(0, 4, 11) {
            let output = solc_compiler_cli::compile_using_cli(compiler_path, input)
                .await
                .context("error compiling using cli")?;
            return Ok(
                serde_json::to_value(output).context("serializing compiler output into value")?
            );
        }
        let solc = foundry_compilers_new::solc::Solc::new_with_version(
            compiler_path,
            compiler_version.to_semver().to_owned(),
        );
        let output = solc
            .async_compile_output(input)
            .await
            .context("compilation")?;
        let output_value =
            serde_json::from_slice(&output).context("deserializing compiler output into value")?;

        Ok(output_value)
    }
}
```

For older compiler versions i.e `<0.4.11` :
   it calls `solc_compiler_cli::compile_using_cli`
   
For newer versions:
   it calls `foundry_compilers_new::solc::Solc::async_compile_output`


16th-Sept-2025 @ 3:04 AM

I figured out how to get the actual bytecode which is deployed from the polkavm or compiled from resolc 
and i got it using this

```
use std::collections::{BTreeMap, BTreeSet};
use resolc::test_utils::build_solidity;

fn main() {
    let source_code = r#"
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.22;

    contract Flipper {
        bool private value;

        constructor(bool initialValue) {
            value = initialValue;
        }

        function flip() public {
            value = !value;
        }

        function get() public view returns (bool) {
            return value;
        }
    }
    "#;
    let mut sources = BTreeMap::new();
    sources.insert("./test.sol".to_owned(), source_code.to_owned());

    let mut remappings = BTreeSet::new();
    remappings.insert("libraries/default/=./".to_owned());

    let output = build_solidity(
        sources,
        BTreeMap::new(),
        Some(remappings),
        revive_llvm_context::OptimizerSettings::cycles(),
    )
    .expect("Test failure");

    println!("{:?}",output)
}

```

the Cargo.toml file looks like this as of now

```
[package]
name = "solidity_compiler_cli"
version = "0.1.0"
edition = "2024"

[dependencies]
resolc = "0.3"
anyhow = "1.0"
serde_json = "1.0"
hex = "0.4" 
revive-llvm-context = "0.3.0"
```

3:28 AM 

next step should be to analyse how this block is working and see the output code

<img width="860" height="391" alt="Screenshot 2025-09-16 at 3 28 10 AM" src="https://github.com/user-attachments/assets/f9fb0dff-62c6-4222-b844-ea503d06fae2" />

``` Note for future Anukul
If the output is taken straight from the terminal or std_out then just make a wrapper such that it will pass the solc version using --solc flag and you are good to go
```

1:06 PM

the command looks like this 

```
/var/folders/95/kg2c09hx00z4_5tg3c2kpz540000gn/T/solidity-compilers/v0.8.22+commit.4fc1097e/solc --combined-json abi,bin,bin-runtime --optimize --optimize-runs 200 /var/folders/95/kg2c09hx00z4_5tg3c2kpz540000gn/T/.tmpgwev2z/.sol
```

which is like 

- solc path - which i can pass to the resolc
- flag - combined-json need to check what to do or how to use it
- optimize - also need to check whether it is available in resolc i dont think so
- file_path

  so i think we should do it one by one, the command should vary for each of these, like first the resolc should be used with the set path , then these --combined-json stuff
  but prior to that lets check whether the output is logged in the console or what? like how are we getting the output.


Lets get all the commands first so that we know all the types

1. Single File

```
/var/folders/95/kg2c09hx00z4_5tg3c2kpz540000gn/T/solidity-compilers/v0.8.22+commit.4fc1097e/solc --combined-json abi,bin,bin-runtime --optimize /var/folders/95/kg2c09hx00z4_5tg3c2kpz540000gn/T/.tmpVTopXW/contracts/Flipper.sol
```

2. Standard JSON

```
/var/folders/95/kg2c09hx00z4_5tg3c2kpz540000gn/T/solidity-compilers/v0.8.22+commit.4fc1097e/solc --combined-json abi,bin,bin-runtime --optimize /var/folders/95/kg2c09hx00z4_5tg3c2kpz540000gn/T/.tmp0Ef6un/contracts/Flipper.sol
```

3. Multi-part files

```
/var/folders/95/kg2c09hx00z4_5tg3c2kpz540000gn/T/solidity-compilers/v0.8.22+commit.4fc1097e/solc --combined-json abi,bin,bin-runtime --optimize --optimize-runs 200 /var/folders/95/kg2c09hx00z4_5tg3c2kpz540000gn/T/.tmpegswfs/Flipper.sol
```

let's check in which format is the output or how are we getting the output and can I run some other command too?

I replaced the CLI Compiler with this - i.e Now it uses resolc

```
pub async fn compile_using_cli(
    compiler_path: &Path, // <-- this is the solc binary
    input: &SolcInput,
) -> Result<solc::CompilerOutput, SolcError> {
    println!("anukul is here for compilation");

    // `resolc` binary (can be absolute path if needed)
    let resolc_bin = "resolc";

    let output = {
        let input = &input.0;
        let input_args = types::InputArgs::from(input);
        let input_files = types::InputFiles::try_from_compiler_input(input).await?;

        // Start with original args from solc
        let mut solc_args = input_args.build();

        // Remove solc-style optimization flags
        solc_args.retain(|arg| arg != "--optimize" && arg != "--optimize-runs");

        // Add resolc-style optimization flag
        solc_args.push("--optimization".to_string());
        solc_args.push("z".to_string());

        // Files (.sol)
        let files = input_files.build()?; // e.g. ["/tmp/Flipper.sol"]

        // Construct new arg order for resolc
        let mut args = Vec::new();
        args.extend(files.iter().map(|p| p.to_string_lossy().to_string())); // .sol files first
        args.push("--solc".to_string());
        args.push(compiler_path.display().to_string()); // actual solc binary
        args.extend(solc_args.into_iter()); // compiler args

        // Debug print
        println!(
            "[compile_using_cli] Running command:\n{} {}",
            resolc_bin,
            args.join(" ")
        );

        Command::new(resolc_bin)
            .args(&args)
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
            .map_err(|err| SolcError::Io(SolcIoError::new(err, Path::new(resolc_bin))))?
    };

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let compiler_output = if output.stderr.is_empty() {
        let output_json: types::OutputJson = serde_json::from_slice(output.stdout.as_slice())?;
        solc::CompilerOutput::try_from(output_json)?
    } else {
        solc::CompilerOutput {
            errors: vec![compiler_error(stderr)],
            sources: BTreeMap::new(),
            contracts: BTreeMap::new(),
        }
    };
    Ok(compiler_output)
}
```

