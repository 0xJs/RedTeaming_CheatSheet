- [OLLVM obfuscator](#OLLVM-obfuscator)
- [Process Hollowing](#Process-Hollowing)

## OLLVM obfuscator
- Suite of tools and techniques designed to transform code into more complex and less readable code. Also used to protect intellectual property and protect against reverse engineering and static analysis.
- Requirements
	- Desktop development with `c++` installed
	- Clang compiler for Windows
	- MSbuild support for LLVM (clang-cl) toolset
	- Compiled OLLVM
		- Pre-compiled ollvm-13.0.1 [here](https://www.unknowncheats.me/forum/downloads.php?do=file&id=37082)
		- Compile ollvm-16 [Following this guide](https://gist.github.com/emanuelduss/c5c3e405035ea4f1f026d7d72fd79071)
	- Project to obfuscate should be a `C` project, no `c++ syntax` or `c++ headers` 

#### Compiling
To compile a Visual Studio solution using OLLVM, the location of the build tools has to be changed. This can be done by adding a new file `Directory.build.props` to the project directory root with the following content:

```xml
<Project>
  <PropertyGroup>
    <LLVMInstallDir>C:\ollvm-16.0.6.0\Release</LLVMInstallDir>
    <LLVMToolsVersion>16.0.6</LLVMToolsVersion>
  </PropertyGroup>
</Project>
```

- Right-Click on the project -> `Properties` -> `General` and change the Platform Toolset to LLVM (clang-cl)
- Go to `C/C++` -> `Command Line` and add obfuscation options
- https://github.com/obfuscator-llvm/obfuscator/wiki
	- [Instructions Substitution](https://github.com/obfuscator-llvm/obfuscator/wiki/Instructions-Substitution) `-mllvm -sub`
	- [Control Flow Splitting](https://github.com/obfuscator-llvm/obfuscator/wiki/Control-Flow-Flattening) `-mllvm -split`
	- [Control Flow Flattening](https://github.com/obfuscator-llvm/obfuscator/wiki/Control-Flow-Flattening) `-mllvm -fla`
	- [Bogus Control Flow](https://github.com/obfuscator-llvm/obfuscator/wiki/Bogus-Control-Flow) `-mllvm -bcf`

#### Simple obfuscation parameters
```
-mllvm -sub -mllvm -split -mllvm -fla -mllvm -bcf
```

#### Heavy obfuscation parameters
```
-mllvm -sub -mllvm -sub_loop=3 -mllvm -split -mllvm -fla -mllvm -bcf -mllvm -bcf_prob=100 -mllvm -bcf_loop=3 -mllvm -split_num=3
```

## Process hollowing
- The embedded PE File doesn't touch disk it stays in memory evading file based detections
	- The PE File should be encrypted or/and obfuscated
- No new process creation, everything happens in the local process. 
- No new thread creation and image loading
- https://github.com/0xJs/ProcessHollowing_MimiKatz