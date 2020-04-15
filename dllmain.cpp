#include <Windows.h>
#include <memory>

#include "hooks.h"
#include "memory.h"
#include "process.h"
#include "bypass.h"

// cheat engine -> new address -> process_name.exe -> find what accesses this address -> open in disassembler -> process_name.exe + 0x0000000, 2 == sizeof({ 0x32, 0x02 })
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        AllocConsole();
        freopen_s(reinterpret_cast<FILE**>(stdin), "CONIN$", "r", stdin);
        freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);

        bypass::hook_crc(0x9D3383); // incredibly none of this is detected by battleye
    }
    else if (reason == DLL_PROCESS_DETACH)
        FreeLibraryAndExitThread(module, 0);
}