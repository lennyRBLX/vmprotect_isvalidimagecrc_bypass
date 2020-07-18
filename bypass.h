#pragma once

namespace bypass {
	constexpr uint64_t image_offset = 0x140000000; // distance between r13 & actual base | pretty sure this never changes
	uint64_t base = reinterpret_cast<uint64_t>(GetModuleHandleA(NULL));
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    
    uint64_t fake_image;

	// duplicates image
	void create_fake_image() {
		if (fake_image) return;

		/* duplicate image, :< */

		fake_image = reinterpret_cast<uint64_t>(VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE));
		memory::write(fake_image, reinterpret_cast<void*>(base), static_cast<size_t>(nt->OptionalHeader.SizeOfImage));
	}

    // finds a section of memory unused by process | should probably be in memory namespace
    uint64_t find_code_cave(size_t size) {
        uint64_t result = NULL;

        size_t located = 0;
        for (size_t i = 0; i < nt->OptionalHeader.SizeOfImage; i++) {
            char* address = reinterpret_cast<char*>(base + nt->OptionalHeader.SizeOfHeaders + i);

            // dont ever do this kids, you might cause an error :O, since its all in a valid image i dont fucking care
            if (*address == 0)
                located++;
            else
                located = 0;

            if (located >= size) {
                result = reinterpret_cast<uint64_t>(address) - located;
                break;
            }
        }

        return result;
    }

	std::pair<uint64_t, size_t> build_shellcode(uint64_t address) {
        uint64_t result = NULL;

        /* dissasembly */

        // get necessary size for trampoline
        size_t assembly_length = 0;
        byte* opcode = NULL;

        while (assembly_length < hooks::long_jmp_size)
            assembly_length += size_of_code(reinterpret_cast<unsigned char*>(address + assembly_length), &opcode);

        /* shellcode */

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

        // setup shellcode
        uint64_t fake_image_offset = fake_image - image_offset;

        // movabs r9, fake_image
        memcpy(
            reinterpret_cast<void*>(reinterpret_cast<uint64_t>(shellcode) + 2),
            reinterpret_cast<void*>(&fake_image_offset), sizeof(void*)
        );

        // relative jmps -> long jmps
        byte* o_buffer = memory::allocate<byte>(assembly_length);
        memory::read(address, o_buffer, assembly_length);

        size_t new_size = assembly_length;
        hooks::fix_trampoline_jmps(reinterpret_cast<void*>(address), o_buffer, new_size);
        std::cout << std::dec << new_size << " | " << assembly_length << std::endl;

        /* allocation */

        result = reinterpret_cast<uint64_t>(VirtualAlloc(NULL, sizeof(shellcode) + assembly_length + hooks::long_jmp_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
        uint32_t location = 0;

        // write in trampoline bytes
        memory::write(result, shellcode, sizeof(shellcode));
        location += sizeof(shellcode);

        // write in original bytes
        memory::write(result + location, o_buffer, new_size);
        memory::free(o_buffer);
        location += new_size;

        // write in jmp back
        hooks::create_jmp(reinterpret_cast<void*>(result + location), reinterpret_cast<void*>(address + assembly_length));

        return std::pair<uint64_t, size_t>(result, assembly_length);
	}

	// xor al, [rdx] -> trampoline
	void hook_crc(uint64_t address) {
		create_fake_image();

        address += base;

        byte* final_opcode = NULL;
        size_t bytes_to_skip = size_of_code(reinterpret_cast<unsigned char*>(address), &final_opcode);

        // creates trampoline
        std::pair<uint64_t, size_t> shell_pair = build_shellcode(address + bytes_to_skip);
        uint64_t shellcode = shell_pair.first;
        size_t assembly_length = shell_pair.second;

        /* vmprotect_byte_search -> trampoline */

        // protect, allows for writing
        DWORD old_flags = memory::protect(address, PAGE_EXECUTE_READWRITE, assembly_length);

        process::suspend();

        // null assembly
        memset(reinterpret_cast<void*>(address), 0x90, assembly_length);

        // -> trampoline
        hooks::create_jmp(reinterpret_cast<void*>(address), reinterpret_cast<void*>(shellcode));

        process::resume();

        // unprotect, unnecessary privileges
        memory::protect(address, old_flags, assembly_length);
	}
};