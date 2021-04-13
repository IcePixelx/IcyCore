module;

#include "Windows.h"
#include <iostream>

export module syscall;

export namespace syscall
{
	std::int8_t copy_size = -1;

#pragma warning( push )
#pragma warning( disable : 6387) // We cannot error check here due to it being a function template. They won't be zero anyway if they were the whole program would crash anyway.

	template<typename T>
	T SystemCall(const char* ntfunction)
	{
		static void* proxy = nullptr; // Init proxy.

		if (copy_size == -1)
		{
			OSVERSIONINFOEX result = { sizeof(OSVERSIONINFOEX), 0, 0, 0, 0, {'\0'}, 0, 0, 0, 0, 0 }; // Initialize new struct.
			reinterpret_cast<NTSTATUS(NTAPI*)(LPOSVERSIONINFO lpVersionInformation)>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion"))((LPOSVERSIONINFO)&result); // Call RtlGetVersion and fill our struct.

			switch (result.dwMajorVersion) // Check which version of windows we have. The syscalls from Windows 7 to Windows 10 are different so we need to adjust the bytes we copy. Differences at end of file.
			{
			case 6:  // Windows 7
				copy_size = 24;
				break;
			case 10: // Windows 10
				copy_size = 15;
				break;
			default:
				copy_size = 15;
				break;
			}
		}

		if (!proxy)
		{
			proxy = VirtualAlloc(nullptr, copy_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate new code section.

			std::uint32_t* function = reinterpret_cast<std::uint32_t*>(GetProcAddress(GetModuleHandle("ntdll.dll"), ntfunction)); // Grab function.

			memcpy(proxy, function, copy_size); // Copy function into our allocated memory.
		}

		return reinterpret_cast<T>(reinterpret_cast<T*>(proxy)); // Return function as template.
	}

#pragma warning( pop ) 

	NTSTATUS NTAPI NtAllocateVirtualMemory
	(   
		HANDLE    ProcessHandle,
		PVOID*    BaseAddress,
		ULONG_PTR ZeroBits,
		PSIZE_T   RegionSize,
		ULONG     AllocationType,
		ULONG     Protect
	)
	{
		return syscall::SystemCall<NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>("NtAllocateVirtualMemory")(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	}

	NTSTATUS NTAPI NtFreeVirtualMemory
	(
		HANDLE  ProcessHandle,
		PVOID*  BaseAddress,
		PSIZE_T RegionSize,
		ULONG   FreeType
	)
	{
		return syscall::SystemCall<NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG)>("NtFreeVirtualMemory")(ProcessHandle, BaseAddress, RegionSize, FreeType);
	}
}

// Windows 7 NtProtectVirtualMemory Assembly
// 
//.text:7DE90068 B8 4D 00 00 00                                          MOV     EAX, 4Dh;                             // MOV NtProtectVirtualMemory Ordinal into EAX
//.text:7DE9006D 33 C9                                                   XOR     ECX, ECX
//.text:7DE9006F 8D 54 24 04                                             LEA     EDX, [ESP + arg_0]
//.text:7DE90073 64 FF 15 C0 00 00 00                                    CALL    LARGE DWORD PTR FS : 0C0h             // Call the heavensgate. (Wow64SystemServiceCall)
//.text:7DE9007A 83 C4 04                                                ADD     ESP, 4                                // Clean up.
//.text:7DE9007D C2 14 00                                                RETN    14h                                   // Stack clean up.

// Windows 10 NtProtectVirtualMemory Assembly
// 
//ZwProtectVirtualMemory(x, x, x, x, x)          B8 50 00 00 00           MOV     EAX, 50h;                            // MOV NtProtectVirtualMemory Ordinal into EAX.
//ZwProtectVirtualMemory(x, x, x, x, x) + 5      BA 00 8E 30 4B           MOV     EDX, OFFSET _Wow64SystemServiceCall; // MOV Wow64SystemServiceCall (heavensgate) into EDX.
//ZwProtectVirtualMemory(x, x, x, x, x) + A      FF D2                    CALL    EDX; Wow64SystemServiceCall();       // CALL EDX (Wow64SystemServiceCall (heavensgate)).
//ZwProtectVirtualMemory(x, x, x, x, x) + C      C2 14 00                 RETN    14h                                  // Stack clean up.