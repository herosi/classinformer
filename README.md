# Class Informer
IDA Class Informer plugin for IDA Pro 9 and 8. It is just a ported version of the [original classinformer](https://sourceforge.net/projects/classinformer/) to work on IDA 8 and 9. Therefore, I will not actively develop it. If you want to improve it, send the PR to me. Do not open an issue for improvements.

 - This plugin has been tested with IDA Pro `9.1`, `9.0 SP1`, `9.0`, `8.4 SP2`, `8.2 SP1` and `8.0` on both 32-bit and 64-bit versions.
   - ***IMPORTANT!!!*** IDA Pro 9.0 ***beta*** is NOT supported. Use released versions.
   - IDA Pro 7.x cannot load this plugin. Use [the original one](https://sourceforge.net/projects/classinformer/).
 - **This plugin only supports parsing MSVC++'s RTTI on PE formatted binaries for x86, x64, ARM and ARM64 for Windows.** I WILL NOT support GCC's RTTI and other architectures.
 - For IDA 9, you just need to install `ClassInformer64.dll`.
 - For IDA 8, you need to install both `ClassInformer_IDA8x64.dll` and `ClassInformer_IDA8x.dll`.
 - If you have both IDA 8 and 9 on your machine, copy them to the IDA's directories according to the versions, or copy all dlls into `%IDAUSR%\plugins`.
   - If you do not know about IDAUSR, see [this blog post](https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr).

## Download
- You can download compiled binaries from the [Releases](../../releases) section.
