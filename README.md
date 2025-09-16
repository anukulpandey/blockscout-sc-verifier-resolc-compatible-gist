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

The logs of sc-verifier looks like this

```
2025-09-16T09:02:24.347641Z  INFO HTTP request{method=POST endpoint=default client_ip=127.0.0.1 request_id=9b7dadd7-6daf-43a2-8220-ba453dc9e795}: smart_contract_verifier_server::services::solidity_verifier: solidity standard-json verification request received chain_id=Some("13939") contract_address=Some("0x00238412a35560917c1ebef6774d36e6af4d9d98")
[verify] Starting verification for contract: compiler_version: Release(ReleaseVersion { version: Version { major: 0, minor: 8, patch: 22 }, commit: "4fc1097e" })
anukul is here for compilation
[compile_using_cli] Running command:
resolc /var/folders/95/kg2c09hx00z4_5tg3c2kpz540000gn/T/.tmpPbkjxv/contracts/Flipper.sol --solc /var/folders/95/kg2c09hx00z4_5tg3c2kpz540000gn/T/solidity-compilers/v0.8.22+commit.4fc1097e/solc --combined-json abi,bin,bin-runtime --optimization z
anukul is here for compilation
[compile_using_cli] Running command:
resolc /var/folders/95/kg2c09hx00z4_5tg3c2kpz540000gn/T/.tmpfIG8sX/contracts/Flipper.sol --solc /var/folders/95/kg2c09hx00z4_5tg3c2kpz540000gn/T/solidity-compilers/v0.8.22+commit.4fc1097e/solc --combined-json abi,bin,bin-runtime --optimization z
Starting contract verification...
No runtime code present on-chain, skipping runtime verification.
Verifying creation code, length: 2372
=== Starting creation code verification ===
On-chain creation code length: 2372
Compiled creation code length: 2340
On-chain creation code (first 256 bytes): 0x50564d00002409000000000000010700c13000c0008004808f08000000000e0000001c0000002a0000003500000040000000520000005d00000063616c6c5f646174615f636f707963616c6c5f646174615f6c6f616463616c6c5f646174615f73697a656765745f73746f726167657365616c5f72657475726e7365745f696d6d757461626c655f646174617365745f73746f7261676576616c75655f7472616e7366657272656405110287140463616c6c871b066465706c6f790688651402874f2b0073017a037f0300040b0424046304b504c004120525053a056a0563067e06bd0604071b072307390808000251081705330730000383770a05280a0595 ... (total 2372 bytes)
Compiled creation code: 0x50564d00002409000000000000010700c13000c0008004808f08000000000e0000001c0000002a0000003500000040000000520000005d00000063616c6c5f646174615f636f707963616c6c5f646174615f6c6f616463616c6c5f646174615f73697a656765745f73746f726167657365616c5f72657475726e7365745f696d6d757461626c655f646174617365745f73746f7261676576616c75655f7472616e7366657272656405110287140463616c6c871b066465706c6f790688651402874f2b0073017a037f0300040b0424046304b504c004120525053a056a0563067e06bd0604071b072307390808000251081705330730000383770a05280a059511f07b10087b1564896475330820649750100205037c78017c797c7a027c7b03978808d4980897aa1097bb18d4ba0ad4a8087c79057c7a047c7b067c7c07979908d4a90997bb1097cc18d4cb0bd4b909979920d489027c79097c7a087c7b0a7c7c0b979908d4a90997bb1097cc18d4cb0bd4b9097c7a0d7c7b0c7c7c0e7c780f97aa08d4ba0a97cc10978818d4c808d4a808978820d498037c78117c7a107c7b127c7c13978808d4a80897bb1097cc18d4cb0bd4b8087c7a157c7b147c7c167c791797aa08d4ba0a97cc10979918d4c909d4a909979920d4890a7c78197c79187c7b1a7c7c1b978808d4980897bb1097cc18d4cb0bd4b8087c791d7c7b1c7c7c1e7c771f979908d4b90997cc10977718d4c707d49707977720d487076f776fa86f396f2a7b5a187b59107b58087b57821008821595111032009511d87b10207b15187b161082897b19088289087b19828510828618330820501004bd016f686f59821a6faa821b086fbb787b18787a10787908787898bc38787c1f98bc30787c1e98bc28787c1d98bc20787c1c98bc18787c1b98bc10787c1a98bb08787b1998ab38787b1798ab30787b1698ab28787b1598ab20787b1498ab18787b1398ab10787b1298aa08787a11989a38787a0f989a30787a0e989a28787a0d989a20787a0c989a18787a0b989a10787a0a98990878790998893878790798893078790698892878790598892078790498891878790398891078790298880878780182102082151882161095112832009511a07b10587b15507b16489515608411e06476828718828910828a0882886f776f996faa6f887b18187b1a107b19087b17491138491130491128491120481140208318831a20831b403309ff33070a03821738821830821928821a206f776f886f996faa7b6a187b69107b68087b679551a082105882155082164895116032009511a07b10587b15509515608411e08272827a08827b108277188283828908828c108288186f746fbb6faa6f276f826fcc6f996f387b17187b1a107b1b087b147b18387b19307b1c287b12208318831a203309ff330b2033070a069551a082105882155095116032008b7910520931c8780883881f8488e05638000001253309040002390a040002ae8a093d080400020133081000028377c887073200009511f07b10087b158475010a02013d0700000251050750100609501008c0019511c0fe7b1038017b1530017b162801951540018411e04921b8004921b0004921a8004921a0008317a0000a07018217b0008218b8008219a800821aa000d49808d4a707d4870752071f01390600000297672098772095771f8477e095788000d878077b1880007b17880094777b179000330740951880004921980050100a54fd33078000646850100c25ff8377646833090a0154161fde009517603308800050100ef6fb8217788218708216608219687b17187b1810d487078868027b1908949894785108ba004921d8004921d0004921c8004921c0009517409518c000501010e3fd821740821858821948821a50847700ffd46707821b08d4b909821b10d4ba0a821b18d4b8084921f8004921f0004921e8004921e0007b1818017b1a10017b1908017b1700019517e0009518000150101212fe9517203308405010145afb821738821830821928821620d49707d48609d47909989920d48707977720d497075107280033081000028388330701284333081000028388330701283733081000028388330701282b646733085010161efe8377330833090a28e7fa646733085010180bfe83783307330933001a0a04280a330933001a0a0401951180fe7b1078017b1570017b166801951580018411e0491178491170491160800033074095186049116850101ceafb33060000023907000002531704628317800033080a010181179c005147a9efe4cd6b52473ce64c6d4a4921b8004921b0004921a8004921a0008317a0000a07018217b0008218b8008219a800821aa000d49808d4a707d487075107673308100002838833070133090a04281c3308100002838833070133090a04280c838833070133090a04014921f8004921f0004921e8004921e0008317e0000a07018217f0008218f8008219e800821ae000d49808d4a707d4870751071a330810000228be390700000256170318330810000228ae816756170365330810000228a14921d8004921d0004921c8004921c0009517209518c00050101ee3fb7c17208e774911184911107b17330780006418491108501020d6fa390804000256289f000d2003040002a0000133071000028378800033092033070a0401492118014921100149210801492100019517409518000150102289fb821740821848821950821a58847bff0088bb01847700ffd4b707492138014921300149212801492120017b1a58017b1950017b1848017b1740019517200195184001501024c3fb33081000028388330733090a0428dffe33075010264afc33070150102842fc82ab7b1b1882ab087b1b2082ab107b1b2882aa187b1a308296829a087b1a829a107b1a088299187b19103202214225a952484992244992244992244992244992244992244992244992244992244992244992542529a524292949a84a494a922449922449922449922449922449922449922449929224294955494a92284925495592922425494a5292aaaa242549492a494a920421240ca5496948848888484444342222498424894414890851a80e89902449928a8888444892489224111111111121094992244932944229942a5453a14a9546444492902484105123108888884644244928552855a91111d188882409850815a1888844484951420881215223221221492291888888888810aa524828499294922400
MatchBuilder created successfully, applying transformations...
Transformations applied.
Transformed compiled code length: 2372
Transformed compiled code (0x): 0x50564d00002409000000000000010700c13000c0008004808f08000000000e0000001c0000002a0000003500000040000000520000005d00000063616c6c5f646174615f636f707963616c6c5f646174615f6c6f616463616c6c5f646174615f73697a656765745f73746f726167657365616c5f72657475726e7365745f696d6d757461626c655f646174617365745f73746f7261676576616c75655f7472616e7366657272656405110287140463616c6c871b066465706c6f790688651402874f2b0073017a037f0300040b0424046304b504c004120525053a056a0563067e06bd0604071b072307390808000251081705330730000383770a05280a059511f07b10087b1564896475330820649750100205037c78017c797c7a027c7b03978808d4980897aa1097bb18d4ba0ad4a8087c79057c7a047c7b067c7c07979908d4a90997bb1097cc18d4cb0bd4b909979920d489027c79097c7a087c7b0a7c7c0b979908d4a90997bb1097cc18d4cb0bd4b9097c7a0d7c7b0c7c7c0e7c780f97aa08d4ba0a97cc10978818d4c808d4a808978820d498037c78117c7a107c7b127c7c13978808d4a80897bb1097cc18d4cb0bd4b8087c7a157c7b147c7c167c791797aa08d4ba0a97cc10979918d4c909d4a909979920d4890a7c78197c79187c7b1a7c7c1b978808d4980897bb1097cc18d4cb0bd4b8087c791d7c7b1c7c7c1e7c771f979908d4b90997cc10977718d4c707d49707977720d487076f776fa86f396f2a7b5a187b59107b58087b57821008821595111032009511d87b10207b15187b161082897b19088289087b19828510828618330820501004bd016f686f59821a6faa821b086fbb787b18787a10787908787898bc38787c1f98bc30787c1e98bc28787c1d98bc20787c1c98bc18787c1b98bc10787c1a98bb08787b1998ab38787b1798ab30787b1698ab28787b1598ab20787b1498ab18787b1398ab10787b1298aa08787a11989a38787a0f989a30787a0e989a28787a0d989a20787a0c989a18787a0b989a10787a0a98990878790998893878790798893078790698892878790598892078790498891878790398891078790298880878780182102082151882161095112832009511a07b10587b15507b16489515608411e06476828718828910828a0882886f776f996faa6f887b18187b1a107b19087b17491138491130491128491120481140208318831a20831b403309ff33070a03821738821830821928821a206f776f886f996faa7b6a187b69107b68087b679551a082105882155082164895116032009511a07b10587b15509515608411e08272827a08827b108277188283828908828c108288186f746fbb6faa6f276f826fcc6f996f387b17187b1a107b1b087b147b18387b19307b1c287b12208318831a203309ff330b2033070a069551a082105882155095116032008b7910520931c8780883881f8488e05638000001253309040002390a040002ae8a093d080400020133081000028377c887073200009511f07b10087b158475010a02013d0700000251050750100609501008c0019511c0fe7b1038017b1530017b162801951540018411e04921b8004921b0004921a8004921a0008317a0000a07018217b0008218b8008219a800821aa000d49808d4a707d4870752071f01390600000297672098772095771f8477e095788000d878077b1880007b17880094777b179000330740951880004921980050100a54fd33078000646850100c25ff8377646833090a0154161fde009517603308800050100ef6fb8217788218708216608219687b17187b1810d487078868027b1908949894785108ba004921d8004921d0004921c8004921c0009517409518c000501010e3fd821740821858821948821a50847700ffd46707821b08d4b909821b10d4ba0a821b18d4b8084921f8004921f0004921e8004921e0007b1818017b1a10017b1908017b1700019517e0009518000150101212fe9517203308405010145afb821738821830821928821620d49707d48609d47909989920d48707977720d497075107280033081000028388330701284333081000028388330701283733081000028388330701282b646733085010161efe8377330833090a28e7fa646733085010180bfe83783307330933001a0a04280a330933001a0a0401951180fe7b1078017b1570017b166801951580018411e0491178491170491160800033074095186049116850101ceafb33060000023907000002531704628317800033080a010181179c005147a9efe4cd6b52473ce64c6d4a4921b8004921b0004921a8004921a0008317a0000a07018217b0008218b8008219a800821aa000d49808d4a707d487075107673308100002838833070133090a04281c3308100002838833070133090a04280c838833070133090a04014921f8004921f0004921e8004921e0008317e0000a07018217f0008218f8008219e800821ae000d49808d4a707d4870751071a330810000228be390700000256170318330810000228ae816756170365330810000228a14921d8004921d0004921c8004921c0009517209518c00050101ee3fb7c17208e774911184911107b17330780006418491108501020d6fa390804000256289f000d2003040002a0000133071000028378800033092033070a0401492118014921100149210801492100019517409518000150102289fb821740821848821950821a58847bff0088bb01847700ffd4b707492138014921300149212801492120017b1a58017b1950017b1848017b1740019517200195184001501024c3fb33081000028388330733090a0428dffe33075010264afc33070150102842fc82ab7b1b1882ab087b1b2082ab107b1b2882aa187b1a308296829a087b1a829a107b1a088299187b19103202214225a952484992244992244992244992244992244992244992244992244992244992244992542529a524292949a84a494a922449922449922449922449922449922449922449929224294955494a92284925495592922425494a5292aaaa242549492a494a920421240ca5496948848888484444342222498424894414890851a80e89902449928a8888444892489224111111111121094992244932944229942a5453a14a9546444492902484105123108888884644244928552855a91111d188882409850815a1888844484951420881215223221221492291888888888810aa5248284992949224000000000000000000000000000000000000000000000000000000000000000000
Creation code verification succeeded!
=== Finished creation code verification ===
Creation verification result: Ok(Some(Match { metadata_match: false, transformations: [Transformation { type: Insert, reason: ConstructorArguments, offset: 2340, id: None }], values: Values { cbor_auxdata: {}, constructor_arguments: Some(b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"), libraries: {}, immutables: {} } }))
Creation code matched successfully!
Finished contract verification. Runtime match: false, Creation match: true
verified iguess
verified result processing started
verified result processing finished VerifyResponse { message: "OK", status: Success, source: Some(Source { file_name: "", contract_name: "Flipper", compiler_version: "v0.8.22+commit.4fc1097e", compiler_settings: "{\"libraries\":{},\"optimizer\":{\"enabled\":true},\"outputSelection\":{\"*\":{\"\":[\"*\"],\"*\":[\"*\"]}}}", source_type: Solidity, source_files: {"contracts/Flipper.sol": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.22;\n\ncontract Flipper {\n    bool private value;\n\n    constructor(bool initialValue) {\n        value = initialValue;\n    }\n\n    function flip() public {\n        value = !value;\n    }\n\n    function get() public view returns (bool) {\n        return value;\n    }\n}\n"}, abi: Some("[{\"inputs\":[{\"internalType\":\"bool\",\"name\":\"initialValue\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[],\"name\":\"flip\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"get\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"), constructor_arguments: Some("0x0000000000000000000000000000000000000000000000000000000000000000"), match_type: Partial, compilation_artifacts: Some("{\"abi\":[{\"inputs\":[{\"internalType\":\"bool\",\"name\":\"initialValue\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[],\"name\":\"flip\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"get\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"}],\"devdoc\":{},\"sources\":{},\"storageLayout\":null,\"userdoc\":{}}"), creation_input_artifacts: Some("{\"cborAuxdata\":{},\"linkReferences\":{},\"sourceMap\":null}"), deployed_bytecode_artifacts: Some("{\"cborAuxdata\":{},\"immutableReferences\":null,\"linkReferences\":{},\"sourceMap\":null}"), is_blueprint: false, libraries: {} }), extra_data: Some(ExtraData { local_creation_input_parts: [BytecodePart { r#type: "main", data: "0x50564d00002409000000000000010700c13000c0008004808f08000000000e0000001c0000002a0000003500000040000000520000005d00000063616c6c5f646174615f636f707963616c6c5f646174615f6c6f616463616c6c5f646174615f73697a656765745f73746f726167657365616c5f72657475726e7365745f696d6d757461626c655f646174617365745f73746f7261676576616c75655f7472616e7366657272656405110287140463616c6c871b066465706c6f790688651402874f2b0073017a037f0300040b0424046304b504c004120525053a056a0563067e06bd0604071b072307390808000251081705330730000383770a05280a059511f07b10087b1564896475330820649750100205037c78017c797c7a027c7b03978808d4980897aa1097bb18d4ba0ad4a8087c79057c7a047c7b067c7c07979908d4a90997bb1097cc18d4cb0bd4b909979920d489027c79097c7a087c7b0a7c7c0b979908d4a90997bb1097cc18d4cb0bd4b9097c7a0d7c7b0c7c7c0e7c780f97aa08d4ba0a97cc10978818d4c808d4a808978820d498037c78117c7a107c7b127c7c13978808d4a80897bb1097cc18d4cb0bd4b8087c7a157c7b147c7c167c791797aa08d4ba0a97cc10979918d4c909d4a909979920d4890a7c78197c79187c7b1a7c7c1b978808d4980897bb1097cc18d4cb0bd4b8087c791d7c7b1c7c7c1e7c771f979908d4b90997cc10977718d4c707d49707977720d487076f776fa86f396f2a7b5a187b59107b58087b57821008821595111032009511d87b10207b15187b161082897b19088289087b19828510828618330820501004bd016f686f59821a6faa821b086fbb787b18787a10787908787898bc38787c1f98bc30787c1e98bc28787c1d98bc20787c1c98bc18787c1b98bc10787c1a98bb08787b1998ab38787b1798ab30787b1698ab28787b1598ab20787b1498ab18787b1398ab10787b1298aa08787a11989a38787a0f989a30787a0e989a28787a0d989a20787a0c989a18787a0b989a10787a0a98990878790998893878790798893078790698892878790598892078790498891878790398891078790298880878780182102082151882161095112832009511a07b10587b15507b16489515608411e06476828718828910828a0882886f776f996faa6f887b18187b1a107b19087b17491138491130491128491120481140208318831a20831b403309ff33070a03821738821830821928821a206f776f886f996faa7b6a187b69107b68087b679551a082105882155082164895116032009511a07b10587b15509515608411e08272827a08827b108277188283828908828c108288186f746fbb6faa6f276f826fcc6f996f387b17187b1a107b1b087b147b18387b19307b1c287b12208318831a203309ff330b2033070a069551a082105882155095116032008b7910520931c8780883881f8488e05638000001253309040002390a040002ae8a093d080400020133081000028377c887073200009511f07b10087b158475010a02013d0700000251050750100609501008c0019511c0fe7b1038017b1530017b162801951540018411e04921b8004921b0004921a8004921a0008317a0000a07018217b0008218b8008219a800821aa000d49808d4a707d4870752071f01390600000297672098772095771f8477e095788000d878077b1880007b17880094777b179000330740951880004921980050100a54fd33078000646850100c25ff8377646833090a0154161fde009517603308800050100ef6fb8217788218708216608219687b17187b1810d487078868027b1908949894785108ba004921d8004921d0004921c8004921c0009517409518c000501010e3fd821740821858821948821a50847700ffd46707821b08d4b909821b10d4ba0a821b18d4b8084921f8004921f0004921e8004921e0007b1818017b1a10017b1908017b1700019517e0009518000150101212fe9517203308405010145afb821738821830821928821620d49707d48609d47909989920d48707977720d497075107280033081000028388330701284333081000028388330701283733081000028388330701282b646733085010161efe8377330833090a28e7fa646733085010180bfe83783307330933001a0a04280a330933001a0a0401951180fe7b1078017b1570017b166801951580018411e0491178491170491160800033074095186049116850101ceafb33060000023907000002531704628317800033080a010181179c005147a9efe4cd6b52473ce64c6d4a4921b8004921b0004921a8004921a0008317a0000a07018217b0008218b8008219a800821aa000d49808d4a707d487075107673308100002838833070133090a04281c3308100002838833070133090a04280c838833070133090a04014921f8004921f0004921e8004921e0008317e0000a07018217f0008218f8008219e800821ae000d49808d4a707d4870751071a330810000228be390700000256170318330810000228ae816756170365330810000228a14921d8004921d0004921c8004921c0009517209518c00050101ee3fb7c17208e774911184911107b17330780006418491108501020d6fa390804000256289f000d2003040002a0000133071000028378800033092033070a0401492118014921100149210801492100019517409518000150102289fb821740821848821950821a58847bff0088bb01847700ffd4b707492138014921300149212801492120017b1a58017b1950017b1848017b1740019517200195184001501024c3fb33081000028388330733090a0428dffe33075010264afc33070150102842fc82ab7b1b1882ab087b1b2082ab107b1b2882aa187b1a308296829a087b1a829a107b1a088299187b19103202214225a952484992244992244992244992244992244992244992244992244992244992244992542529a524292949a84a494a922449922449922449922449922449922449922449929224294955494a92284925495592922425494a5292aaaa242549492a494a920421240ca5496948848888484444342222498424894414890851a80e89902449928a8888444892489224111111111121094992244932944229942a5453a14a9546444492902484105123108888884644244928552855a91111d188882409850815a1888844484951420881215223221221492291888888888810aa524828499294922400" }], local_deployed_bytecode_parts: [BytecodePart { r#type: "main", data: "0x50564d00002409000000000000010700c13000c0008004808f08000000000e0000001c0000002a0000003500000040000000520000005d00000063616c6c5f646174615f636f707963616c6c5f646174615f6c6f616463616c6c5f646174615f73697a656765745f73746f726167657365616c5f72657475726e7365745f696d6d757461626c655f646174617365745f73746f7261676576616c75655f7472616e7366657272656405110287140463616c6c871b066465706c6f790688651402874f2b0073017a037f0300040b0424046304b504c004120525053a056a0563067e06bd0604071b072307390808000251081705330730000383770a05280a059511f07b10087b1564896475330820649750100205037c78017c797c7a027c7b03978808d4980897aa1097bb18d4ba0ad4a8087c79057c7a047c7b067c7c07979908d4a90997bb1097cc18d4cb0bd4b909979920d489027c79097c7a087c7b0a7c7c0b979908d4a90997bb1097cc18d4cb0bd4b9097c7a0d7c7b0c7c7c0e7c780f97aa08d4ba0a97cc10978818d4c808d4a808978820d498037c78117c7a107c7b127c7c13978808d4a80897bb1097cc18d4cb0bd4b8087c7a157c7b147c7c167c791797aa08d4ba0a97cc10979918d4c909d4a909979920d4890a7c78197c79187c7b1a7c7c1b978808d4980897bb1097cc18d4cb0bd4b8087c791d7c7b1c7c7c1e7c771f979908d4b90997cc10977718d4c707d49707977720d487076f776fa86f396f2a7b5a187b59107b58087b57821008821595111032009511d87b10207b15187b161082897b19088289087b19828510828618330820501004bd016f686f59821a6faa821b086fbb787b18787a10787908787898bc38787c1f98bc30787c1e98bc28787c1d98bc20787c1c98bc18787c1b98bc10787c1a98bb08787b1998ab38787b1798ab30787b1698ab28787b1598ab20787b1498ab18787b1398ab10787b1298aa08787a11989a38787a0f989a30787a0e989a28787a0d989a20787a0c989a18787a0b989a10787a0a98990878790998893878790798893078790698892878790598892078790498891878790398891078790298880878780182102082151882161095112832009511a07b10587b15507b16489515608411e06476828718828910828a0882886f776f996faa6f887b18187b1a107b19087b17491138491130491128491120481140208318831a20831b403309ff33070a03821738821830821928821a206f776f886f996faa7b6a187b69107b68087b679551a082105882155082164895116032009511a07b10587b15509515608411e08272827a08827b108277188283828908828c108288186f746fbb6faa6f276f826fcc6f996f387b17187b1a107b1b087b147b18387b19307b1c287b12208318831a203309ff330b2033070a069551a082105882155095116032008b7910520931c8780883881f8488e05638000001253309040002390a040002ae8a093d080400020133081000028377c887073200009511f07b10087b158475010a02013d0700000251050750100609501008c0019511c0fe7b1038017b1530017b162801951540018411e04921b8004921b0004921a8004921a0008317a0000a07018217b0008218b8008219a800821aa000d49808d4a707d4870752071f01390600000297672098772095771f8477e095788000d878077b1880007b17880094777b179000330740951880004921980050100a54fd33078000646850100c25ff8377646833090a0154161fde009517603308800050100ef6fb8217788218708216608219687b17187b1810d487078868027b1908949894785108ba004921d8004921d0004921c8004921c0009517409518c000501010e3fd821740821858821948821a50847700ffd46707821b08d4b909821b10d4ba0a821b18d4b8084921f8004921f0004921e8004921e0007b1818017b1a10017b1908017b1700019517e0009518000150101212fe9517203308405010145afb821738821830821928821620d49707d48609d47909989920d48707977720d497075107280033081000028388330701284333081000028388330701283733081000028388330701282b646733085010161efe8377330833090a28e7fa646733085010180bfe83783307330933001a0a04280a330933001a0a0401951180fe7b1078017b1570017b166801951580018411e0491178491170491160800033074095186049116850101ceafb33060000023907000002531704628317800033080a010181179c005147a9efe4cd6b52473ce64c6d4a4921b8004921b0004921a8004921a0008317a0000a07018217b0008218b8008219a800821aa000d49808d4a707d487075107673308100002838833070133090a04281c3308100002838833070133090a04280c838833070133090a04014921f8004921f0004921e8004921e0008317e0000a07018217f0008218f8008219e800821ae000d49808d4a707d4870751071a330810000228be390700000256170318330810000228ae816756170365330810000228a14921d8004921d0004921c8004921c0009517209518c00050101ee3fb7c17208e774911184911107b17330780006418491108501020d6fa390804000256289f000d2003040002a0000133071000028378800033092033070a0401492118014921100149210801492100019517409518000150102289fb821740821848821950821a58847bff0088bb01847700ffd4b707492138014921300149212801492120017b1a58017b1950017b1848017b1740019517200195184001501024c3fb33081000028388330733090a0428dffe33075010264afc33070150102842fc82ab7b1b1882ab087b1b2082ab107b1b2882aa187b1a308296829a087b1a829a107b1a088299187b19103202214225a952484992244992244992244992244992244992244992244992244992244992244992542529a524292949a84a494a922449922449922449922449922449922449922449929224294955494a92284925495592922425494a5292aaaa242549492a494a920421240ca5496948848888484444342222498424894414890851a80e89902449928a8888444892489224111111111121094992244932944229942a5453a14a9546444492902484105123108888884644244928552855a91111d188882409850815a1888844484951420881215223221221492291888888888810aa524828499294922400" }] }), post_action_responses: Some(PostActionResponses { lookup_methods: None }) }
final result processing finished
```

seems like the contract is verified but it doesnt get stored in the blockscout database or in the backend service, rn its too difficult to verify all the logs so i will run the backend server and explorer service along with the smart-contract-verifier, wont be using visualiser, stats or other stuff. So that it will be easier for me to pin point the problem from where its coming.

I ran this in terminal to make request to the backend service for verification

```
 curl -L \
  --request POST \
  --url 'http://localhost/api/v2/smart-contracts/0x00238412a35560917c1ebef6774d36e6af4d9d98/verification/via/standard-input' \
  --header 'Content-Type: multipart/form-data' \
  --form 'compiler_version=v0.8.22+commit.4fc1097e' \
  --form 'contract_name=Flipper' \
  --form 'files[0]=@standard.json;type=application/json' \
  --form 'autodetect_constructor_args=false' \
  --form 'license_type=MIT'
```

it returned 

```
{"message":"Smart-contract verification started"}
```

so feels like the smart contract is verified and returns the proper output but somehow not stored in the database, what i can speculate is that it can be issue in storing to postgres.

4:45 PM IST

got this

```
0x41c37c250a6cdefc84c795d71c47399d96eb3eef813b (truncated)
2025-09-16T11:14:21.202 [error] Task #PID<0.53169.0> started from #PID<0.9149.0> terminating
** (MatchError) no match of right hand side value: %{"contracts/Flipper.sol" => "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.22;\n\ncontract Flipper {\n    bool private value;\n\n    constructor(bool initialValue) {\n        value = initialValue;\n    }\n\n    function flip() public {\n        value = !value;\n    }\n\n    function get() public view returns (bool) {\n        return value;\n    }\n}\n"}
    (explorer 9.1.0) lib/explorer/smart_contract/solidity/publisher.ex:247: Explorer.SmartContract.Solidity.Publisher.process_rust_verifier_response/6
    (explorer 9.1.0) lib/explorer/smart_contract/solidity/publisher_worker.ex:62: Explorer.SmartContract.Solidity.PublisherWorker.broadcast/4
    (elixir 1.17.3) lib/task/supervised.ex:101: Task.Supervised.invoke_mfa/2
Function: #Function<3.82049945/0 in Que.Job.perform/1>
    Args: []
2025-09-16T11:14:21.593 application=indexer fetcher=coin_balance_catchup count=100 error_count=100 [error] failed to fetch: 
```

which means that the response emitted by the smart-contract-verifier doesnt fit the input required by the blockscout explorer backend, so need to parse the response in that way from the `resolc` compiled result.
