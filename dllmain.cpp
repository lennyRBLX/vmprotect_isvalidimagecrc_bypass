#include <Windows.h>
#include <memory>

#include "hooks.h"
#include "memory.h"

#define offset_vmprotect_byte_search 0x63D2A44 + 2

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        AllocConsole();
        freopen_s(reinterpret_cast<FILE**>(stdin), "CONIN$", "r", stdin);
        freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
        
        uint64_t base = reinterpret_cast<uint64_t>(GetModuleHandleA(NULL));

        // get image info
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(GetModuleHandleA(NULL));
        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        IMAGE_SECTION_HEADER* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(nt + 1);
        
        /* duplicate image, :< */

        byte* fake_image = reinterpret_cast<byte*>(VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE));
        memory::write(reinterpret_cast<uint64_t>(fake_image), reinterpret_cast<void*>(base), nt->OptionalHeader.SizeOfImage);

        std::cout << std::hex << reinterpret_cast<void*>(fake_image) << std::endl;

        /* disassembly */

        // get necessary size for trampoline
        size_t assembly_length = 0;
        byte* opcode = NULL;

        while (assembly_length < hooks::long_jmp_size)
            assembly_length += size_of_code(reinterpret_cast<unsigned char*>(base + offset_vmprotect_byte_search + assembly_length), &opcode);

        // create shellcode
        byte shellcode[] = {
            0x49, 0xB9, // movabs r9, ->
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fake_image
            0x49, 0x89, 0xD2, // mov r10, rdx
            0x4C, 0x29, 0xEA, // sub rdx, r13
            0x4C, 0x01, 0xCA, // add rdx, r9
            0x32, 0x02, // xor al, [rdx]
            0x4C, 0x89, 0xD2, // mov rdx, r10
            0x4D, 0x31, 0xD2, // xor r10, r10
            0x90 // nop
        };

        /* shell_address = find_image_code_cave(sizeof(shellcode)) */

        void* shell_address = NULL;
        size_t i = 0;

        // replacement: shell_address = reinterpret_cast<void*>(VirtualAlloc(NULL, sizeof(shellcode) + assembly_length + hooks::long_jmp_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
        while (shell_address == NULL) {
            i++;
            shell_address = reinterpret_cast<void*>(VirtualAlloc(reinterpret_cast<void*>(base + nt->OptionalHeader.SizeOfImage + (0x10000 * i)), sizeof(shellcode) + assembly_length + hooks::long_jmp_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
        }

        std::cout << std::hex << shell_address << std::endl;

        uint64_t fake_image_offset = reinterpret_cast<uint64_t>(fake_image) - 0x140000000;

        std::cout << fake_image_offset << std::endl;

        /* setup(shellcode) */

        // movabs r9, fake_image
        memcpy(reinterpret_cast<void*>(reinterpret_cast<uint64_t>(shellcode) + 2), reinterpret_cast<void*>(&fake_image_offset), sizeof(void*)); // the 140000000 is the offset between r13's base address & the real base

        // write in trampoline bytes
        memory::write(reinterpret_cast<uint64_t>(shell_address), shellcode, sizeof(shellcode));

        /* write(trampoline, original_bytes) */

        // fix relative jmps, translates to long jmps
        byte* o_buffer = memory::allocate<byte>(assembly_length);
        memory::read(base + offset_vmprotect_byte_search, o_buffer, assembly_length);

        size_t new_size = assembly_length;
        hooks::fix_trampoline_jmps(reinterpret_cast<void*>(base + offset_vmprotect_byte_search), o_buffer, new_size);
        memory::write(reinterpret_cast<uint64_t>(shell_address) + sizeof(shellcode), o_buffer, new_size);
        memory::free(o_buffer);

        std::cout << std::dec << new_size << " | " << assembly_length << std::endl;

        hooks::create_jmp(reinterpret_cast<void*>(reinterpret_cast<uint64_t>(shell_address) + sizeof(shellcode) + new_size), reinterpret_cast<void*>(base + offset_vmprotect_byte_search + assembly_length));

        /* vmprotect_byte_search -> trampoline */

        // protect, allows for writing
        DWORD old_flags = memory::protect(base + offset_vmprotect_byte_search - 2, PAGE_EXECUTE_READWRITE, assembly_length + 2);

        // null assembly
        memset(reinterpret_cast<void*>(base + offset_vmprotect_byte_search - 2), 0x90, assembly_length + 2);

        // -> trampoline
        hooks::create_jmp(reinterpret_cast<void*>(base + offset_vmprotect_byte_search - 2), shell_address);

        // unprotect, unnecessary privileges
        memory::protect(base + offset_vmprotect_byte_search - 2, old_flags, assembly_length + 2);
    }
    else if (reason == DLL_PROCESS_DETACH)
        FreeLibraryAndExitThread(module, 0);
}