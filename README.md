# vmprotect_isvalidimagecrc_bypass
Bypasses VMProtect's IsValidImageCRC inline function

Duplicates the process image to a R/W section of memory and writes a custom trampoline-based method over VMProtect to search the duplicated process image.

Tested Versions:
- 3.4
- 3.1
