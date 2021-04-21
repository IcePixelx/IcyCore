module;

#include "Windows.h"
#include <iostream>
#include <string>

export module syscall;

import modules;

export namespace Syscall
{
	SIZE_T copy_size = -1; // Copy size for certain Windows version.

#pragma warning( push )
#pragma warning( disable : 6387) // We cannot error check here due to it being a function template. They won't be zero anyway if they were the whole program would crash anyway.

	/*
	*  This function is a template that performs a system call.
	*  The function gets casted to the template that gets provided when the function gets called.
	* 
	*  @calling convention: Compiler handled.
	*  @parameters:         Constant std::string ntfunction, string that holds the function we wanna perform a system call with
	*  @return:             Returns template function call, in this case it will be a system call and the return outcome will be NTSTATUS.
	*/

	template<typename T>
	T SystemCall(const std::string ntfunction)
	{
		static void* proxy = nullptr; // Initialize proxy variable.

		if (copy_size == -1)
		{
			OSVERSIONINFOEX result = { sizeof(OSVERSIONINFOEX), 0, 0, 0, 0, {'\0'}, 0, 0, 0, 0, 0 }; // Initialize new struct.
			Modulemanager::GetModule("ntdll.dll")->GetExportedFunction("RtlGetVersion").R_Cast<NTSTATUS(NTAPI*)(LPOSVERSIONINFO lpVersionInformation)>()((LPOSVERSIONINFO)&result); // Call RtlGetVersion and fill our result struct.

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
			const NTSTATUS allocate_result = Modulemanager::GetModule("ntdll.dll")->GetExportedFunction("NtAllocateVirtualMemory") // Grab NtAllocateVirtualMemory export and call it to allocate a new code section.
				.R_Cast<NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>() // Function cast.
				(reinterpret_cast<HANDLE>(-1), &proxy, NULL, &copy_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Arguments of function.

			std::uint32_t* function = Modulemanager::GetModule("ntdll.dll")->GetExportedFunction(ntfunction).R_Cast<std::uint32_t*>(); // Grab NT Function.

			memcpy(proxy, function, copy_size); // Copy function into our newly allocated code section.
		}

		return reinterpret_cast<T>(reinterpret_cast<T*>(proxy)); // Return function as template.
	}

#pragma warning( pop ) 

	/*
	*  Wrapper function that performs a system call as NtAllocateVirtualMemory.
	* 
	*  @calling convention: __stdcall (NTAPI)
	*  @parameters:         Parameters are the same as NtAllocateVirtualMemory. Nothing to say about here.
	*  @return:             Will return NTSTATUS of the system call as a result.
	*/

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
		return Syscall::SystemCall<NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>("NtAllocateVirtualMemory")(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	}

	/*
	*  Wrapper function that performs a system call as NtFreeVirtualMemory.
	*
	*  @calling convention: __stdcall (NTAPI)
	*  @parameters:         Parameters are the same as NtFreeVirtualMemory. Nothing to say about here.
	*  @return:             Will return NTSTATUS of the system call as a result.
	*/

	NTSTATUS NTAPI NtFreeVirtualMemory
	(
		HANDLE  ProcessHandle,
		PVOID*  BaseAddress,
		PSIZE_T RegionSize,
		ULONG   FreeType
	)
	{
		return Syscall::SystemCall<NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG)>("NtFreeVirtualMemory")(ProcessHandle, BaseAddress, RegionSize, FreeType);
	}

	/*
	*  Wrapper function that performs a system call as NtProtectVirtualMemory.
	* 
	*  @calling convetion: __stdcall (NTAPI)
	*  @parameters:        Parameters are the same as NtFreeVirtualMemory. Nothing to say about here.
	*  @return:            Will return NTSTATUS of the system call as a result.
	*/

	NTSTATUS NTAPI NtProtectVirtualMemory
	(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		PULONG NumberOfBytesToProtect,
		ULONG NewAccessProtection,
		PULONG OldAccessProtection
	)
	{
		return Syscall::SystemCall<NTSTATUS(NTAPI*)(HANDLE, PVOID*, PULONG, ULONG, PULONG)>("NtProtectVirtualMemory")(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	}
}

// Windows 7 NtProtectVirtualMemory Assembly
// 
//.text:7DE90068 B8 4D 00 00 00                                          MOV     EAX, 4Dh;                             // MOV NtProtectVirtualMemory Ordinal into EAX
//.text:7DE9006D 33 C9                                                   XOR     ECX, ECX
//.text:7DE9006F 8D 54 24 04                                             LEA     EDX, [ESP + arg_0]
//.text:7DE90073 64 FF 15 C0 00 00 00                                    CALL    LARGE DWORD PTR FS : 0C0h             // CALL the heavensgate. (Wow64SystemServiceCall)
//.text:7DE9007A 83 C4 04                                                ADD     ESP, 4                                // Clean up.
//.text:7DE9007D C2 14 00                                                RETN    14h                                   // Stack clean up.

// Windows 10 NtProtectVirtualMemory Assembly
// 
//ZwProtectVirtualMemory(x, x, x, x, x)          B8 50 00 00 00           MOV     EAX, 50h;                            // MOV NtProtectVirtualMemory Ordinal into EAX.
//ZwProtectVirtualMemory(x, x, x, x, x) + 5      BA 00 8E 30 4B           MOV     EDX, OFFSET _Wow64SystemServiceCall; // MOV Wow64SystemServiceCall (heavensgate) into EDX.
//ZwProtectVirtualMemory(x, x, x, x, x) + A      FF D2                    CALL    EDX; Wow64SystemServiceCall();       // CALL EDX (Wow64SystemServiceCall (heavensgate)).
//ZwProtectVirtualMemory(x, x, x, x, x) + C      C2 14 00                 RETN    14h                                  // Stack clean up.