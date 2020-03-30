#pragma once

#include <cstdint>
#include <memory>
#include <iostream>

namespace {
	namespace memory {
		DWORD protect(uint64_t address, DWORD flags, size_t size = 0) {
			DWORD old = 0;
			VirtualProtect((void*)address, size, flags, &old);

			return old;
		}

		template <typename R, typename A>
		R* allocate(A size = 0) {
			return reinterpret_cast<R*>(
				VirtualAlloc(NULL, static_cast<size_t>(size), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
				);
		}

		template <typename A>
		bool free(A* memory_block) {
			return VirtualFree(memory_block, NULL, MEM_RELEASE);
		}

		void* resolve_relative(_In_ void* Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
			__try {
				if (Instruction != 0) {
					uint64_t Instr = (uint64_t)Instruction;
					long RipOffset = *(long*)(Instr + OffsetOffset);
					void* ResolvedAddr = (void*)(Instr + InstructionSize + RipOffset);

					return ResolvedAddr;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}

			return 0;
		}

		template <typename A>
		bool read(uint64_t address, A* buffer, size_t size = 0) {
			__try {
				DWORD old_flags = protect(address, PAGE_EXECUTE_READWRITE, size);

				size_t copied = 0;
				bool result = ReadProcessMemory(GetCurrentProcess(), (void*)address, buffer, size, &copied);

				protect(address, old_flags, size);

				return result;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}

			return false;
		}

		template <typename A>
		bool write(uint64_t address, A* buffer, size_t size = 0) {
			__try {
				DWORD old_flags = protect(address, PAGE_EXECUTE_READWRITE, size);

				size_t copied = 0;
				bool result = WriteProcessMemory(GetCurrentProcess(), (void*)address, buffer, size, &copied);

				protect(address, old_flags, size);

				return result;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}

			return false;
		}
	}
}