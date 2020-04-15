#pragma once

#include <tlhelp32.h>

namespace process {
    // trust me i fucking hate this, but its the only way
	void suspend() {
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

		THREADENTRY32 entry; entry.dwSize = sizeof(THREADENTRY32);
		Thread32First(snapshot, &entry);

		do {
			if (entry.th32OwnerProcessID == GetCurrentProcessId() && entry.th32ThreadID != GetCurrentThreadId()) {
				HANDLE handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
				SuspendThread(handle);
				CloseHandle(handle);
			}
		} while (Thread32Next(snapshot, &entry));

		CloseHandle(snapshot);
	}

    void resume() {
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

		THREADENTRY32 entry; entry.dwSize = sizeof(THREADENTRY32);
		Thread32First(snapshot, &entry);

		do {
			if (entry.th32OwnerProcessID == GetCurrentProcessId() && entry.th32ThreadID != GetCurrentThreadId()) {
				HANDLE handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
				ResumeThread(handle);
				CloseHandle(handle);
			}
		} while (Thread32Next(snapshot, &entry));

		CloseHandle(snapshot);
    }
};