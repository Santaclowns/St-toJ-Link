This is a modified version of [SEGGER STLinkReflash utility](https://www.segger.com/downloads/jlink#STLink_Reflash)

You will probably have to downgrade your St-Link to an older driver. Tested and works on cloned ST-Link using: 
[STSW-LINK007 2.36.26 version](https://www.st.com/en/development-tools/stsw-link007.html)

**How to:**

   Windows:
1. Unpack St-toJ-.zip
2. Make sure .exe and .dll is in the same folder
3. Download and run [STSW-LINK007], follow instructions to upgrade firmware.
4. Done

MacOS/Linux:
1. Don't know, was originally made for Windows only
___
Thanks to [NSA/Ghidra](https://github.com/NationalSecurityAgency/ghidra)
It's as simple as modifying the following binary offsets

2566 (break) 3C -> 38

2567 (new)   40 -> C0

26B2 (break) 3C -> 38

26B3 (new)   4A -> C0

Additional .gzf file and .c export provided
