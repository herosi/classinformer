Before building this solution, build support libs first.

Find and open PropertySheet.props. Change the paths to the proper ones.

Open .sln file. Navigate to View > Property Manager or View > Other Windows > Property Manager to view the property sheet. Compile the lib project for Release/ReleaseEA64 on x64. 

On IDA Pro 8.4, chnage the x64_win_vc_32 and x64_win_vc_64 library directory to x64_win_vc_32_pro and x64_win_vc_64_pro, which means add the "_pro" postfix.
Compile the Plugin projects on each release.
