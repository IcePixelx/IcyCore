module;

#include "Windows.h"
#include <iostream>
#include <functional>

export module syscall;

export namespace syscall
{
	template<typename T>
	T SystemCall(const char* ntfunction)
	{
		static void* proxy = nullptr; // Init proxy.

		if (!proxy)
		{
			proxy = VirtualAlloc(nullptr, 15, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate new code section.

#pragma warning( push )
#pragma warning( disable : 6387) // We cannot error check here due to it being a function template. They won't be zero anyway if they were the whole program would crash anyway.

			std::uint32_t* function = reinterpret_cast<std::uint32_t*>(GetProcAddress(GetModuleHandle("ntdll.dll"), ntfunction)); // Grab function.

			memcpy(proxy, function, 15); // Copy function into our allocated memory.

#pragma warning( pop ) 

		}

		return reinterpret_cast<T>(reinterpret_cast<T*>(proxy)); // Return function as template.
	}

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