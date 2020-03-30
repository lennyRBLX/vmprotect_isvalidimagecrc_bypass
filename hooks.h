#pragma once

#include "memory.h"
#include "ld_asm.h"

namespace hooks {
	size_t relative_jmp_size = 5;
	size_t long_jmp_size = 15;

	bool create_relative_jmp(void* from, void* to) {
		byte shellcode[] = {
			0xE9,
			0x00, 0x00, 0x00, 0x00
		};

		*(DWORD*)(shellcode + 1) = reinterpret_cast<DWORD>(to) - reinterpret_cast<DWORD>(from) - sizeof(shellcode);

		return memory::write(reinterpret_cast<uint64_t>(from), &shellcode, sizeof(shellcode));
	}

	bool create_jmp(void* from, void* to) {
		byte shellcode[] = {
			0xFF, 0x25,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x90
		};

		*(uint64_t*)(shellcode + 6) = reinterpret_cast<uint64_t>(to);

		return memory::write(reinterpret_cast<uint64_t>(from), &shellcode, sizeof(shellcode));
	}

	size_t calculate_trampoline_size(void* from, void* to) {
		size_t result = 0;
		
		uint64_t distance = reinterpret_cast<uint64_t>(from) - reinterpret_cast<uint64_t>(to);
		if (distance != 0) {
			byte* opcode = NULL;
			if (distance <= static_cast<uint64_t>(0x7ffffff)) {
				// relative
				while (result < relative_jmp_size)
					result += size_of_code(reinterpret_cast<unsigned char*>(reinterpret_cast<uint64_t>(from) + result), &opcode);
			}
			else {
				// long
				while (result < long_jmp_size)
					result += size_of_code(reinterpret_cast<unsigned char*>(reinterpret_cast<uint64_t>(from) + result), &opcode);
			}
		}

		return result;
	}

	size_t relative_jmp_to_long(byte* buffer, size_t length) {
		size_t result = length;

		// gather new necessary size
		for (size_t i = 0; i < length; i++) {
			byte current_bit = buffer[i];
			byte* opcode = NULL;
			if (current_bit == 0xE9 && size_of_code(buffer + i, &opcode) == 5 && *opcode == 0xE9) // relative
				result += (long_jmp_size - relative_jmp_size);
		}

		result--;
		return result;
	}

	void fix_trampoline_jmps(void* from, byte*& buffer, size_t& length) { // translates relative jmps to long jmps
		size_t new_size = relative_jmp_to_long(buffer, length);
		byte* n_buffer = memory::allocate<byte>(new_size);
		size_t buffer_i = 0;

		// overwrite relative jmps with long jmps
		for (size_t i = 0; i < length; i++) {
			byte current_bit = buffer[i];
			byte* opcode = NULL;

			if (current_bit == 0xE9 && size_of_code(buffer + i, &opcode) == 5 && *opcode == 0xE9) { // relative
				uint64_t relative_address = reinterpret_cast<uint64_t>(memory::resolve_relative(reinterpret_cast<void*>(reinterpret_cast<uint64_t>(from) + i), 1, relative_jmp_size));
				create_jmp(n_buffer + buffer_i, reinterpret_cast<void*>(relative_address));

				buffer_i += long_jmp_size;
				i += relative_jmp_size - 1;
			}
			else {
				n_buffer[buffer_i] = current_bit;
				buffer_i++;
			}
		}

		memory::free(buffer);
		buffer = n_buffer;
		length = new_size + 1;
	}

	// past this is unnecessary, junk code if u will
}