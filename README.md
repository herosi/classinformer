# classinformer-ida8
IDA Class Informer plugin for IDA 8.x

Changelog from the original v2.6
- Updated to IDA SDK 8.2 and MSVC 2019
- Updated the plugin form to the new one to work with IDA SDK 8.2
- Created a plugin to analyze PE32 on IDA 64 (IDA_ClassInformer_PlugIn3264.dlL) because IDA is currently stopping to use IDA for 32-bit.
- Linked VC++ runtime statically (/MT*)
