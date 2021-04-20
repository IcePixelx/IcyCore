module;

#include "Windows.h"
#include <iostream>
#include <string>
#include <map>

export module heavensgate;

import modules;
import syscall;

export namespace Heavensgate
{
	namespace ordinal
	{
		std::int32_t nt_allocate_virtual_memory = 0x0;
	}

	// Variables
	void* new_heavens_gate = nullptr;
	void* map_return_address = nullptr;
	Modulemanager::MemoryModules* ntdll = nullptr;

	// Pre-Define
	std::int32_t GetOrdinal(const std::string ntapi);

	NTSTATUS __stdcall hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
	{
		return 0xC00000E5; // Make it fail as a test.
	}

	void* GetGateAddress()
	{
		static void* ret_ = nullptr;

		if (ret_)
			return ret_;

		__asm mov eax, dword ptr fs : [0xC0] // Grab the fastsyscall addr from TIB.
		__asm mov ret_, eax // Move it into our retn value.

		return ret_; // Return the gate addr.
	}

	void __declspec(naked) hkWow64Transition()
	{
		// eax holds the ordinal.
		__asm
		{
			cmp eax, ordinal::nt_allocate_virtual_memory // Is the ordinal the virtualallocates one?
			je hook_nt_allocate_virtual_memory // If so jump to it.
			jmp call_original // Jump to original.

hook_nt_allocate_virtual_memory:
			mov eax, hkNtAllocateVirtualMemory // Move our func into eax.
			mov [esp + 0], eax // Replace latest returnaddr with our func this will cause the original function to jump to our hook instead of its supposed destination.
			// From observing the last returnaddress always resides in [esp + 0].
			// With this we can modify eax which will be the return value after the actual syscall in 64bit went through.
			// So now we can modify parameters when our hook gets called and the returnvalue which gives us the complete control as when using a normal hook.
			mov eax, ordinal::nt_allocate_virtual_memory // Give eax the ordinal again.
			jmp call_original 

call_original:
			jmp new_heavens_gate // Jump to our new allocated heavensgate.
		}
	}

	bool PrepHeavensGate()
	{
		ntdll = Modulemanager::GetModule("ntdll.dll");
		ordinal::nt_allocate_virtual_memory = GetOrdinal("NtAllocateVirtualMemory");
		if (ordinal::nt_allocate_virtual_memory == -1) // Ordinal was not found.
			return false;

		return true;
	}

	std::int32_t GetOrdinal(const std::string ntapi)
	{
		MemoryAddress api = ntdll->GetExportedFunction(ntapi);

		if (api && api.CheckBytes({ 0xB8 })) // Valid function that performs a system call?
		{
			return api.OffsetSelf().GetValue<std::int32_t>(); // If yes return the next 4 bytes which will be the ordinal.
		}

		return -1; // error handling.
	}

	bool PatchHeavensGate(void* gate_address, const void* buffer, const std::ptrdiff_t size)
	{
		ULONG protect_size = 16;
		ULONG old_protection = 0;

		// Change heavensgate page protection so we can write to it.
		if (const NTSTATUS protect_status = Syscall::NtProtectVirtualMemory(reinterpret_cast<HANDLE>(-1), &gate_address, &protect_size, PAGE_EXECUTE_READWRITE, &old_protection);
			protect_status != 0) // 0 is STATUS_SUCCESS.
			return false;

		if (!memcpy(gate_address, buffer, size)) // Patch the gate so it points to our hook.
			return false;

		protect_size = 16; // NtProtectvirtualMemory modifies protect_size to 1000 so we need to reset it.

		// Restore page protection.
		if (const NTSTATUS protect_status = Syscall::NtProtectVirtualMemory(reinterpret_cast<HANDLE>(-1), &gate_address, &protect_size, old_protection, &old_protection);
			protect_status != 0) // 0 is STATUS_SUCCESS.
			return false;

		return true;
	}

	bool HookHeavensGate()
	{
		if (!PrepHeavensGate())
			return false;

		if (!GetGateAddress())
			return false;

		void* hook_gate = &hkWow64Transition; // Grab the address of our hooking function.

		// Push Detour.
		// Basically a jmp but we push a new returnaddress onto the stack and pop it with ret to get to that location.
		std::uint8_t trampoline_bytes[] =
		{
			0x68, 0x00, 0x00, 0x00, 0x00,       // push 0xADDRESS
			0xC3,                               // ret
			0x90, 0x90, 0x90                    // nop, nop, nop
		};

		if (!memcpy(&trampoline_bytes[1], &hook_gate, 4)) // Copy our function address into the trampoline.
			return false;

		// Allocate a new code section.
		SIZE_T allocate_size = 16;
		if (const NTSTATUS allocate_result = Syscall::NtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &new_heavens_gate, NULL, &allocate_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			allocate_result != 0) // 0 is STATUS_SUCCESS.
			return false;

		if (!new_heavens_gate) // Is the gate valid?
			return false;

		if (!memcpy(new_heavens_gate, GetGateAddress(), 9)) // Copy the gate into our allocated code section.
			return false;

		if (!PatchHeavensGate(GetGateAddress(), trampoline_bytes, sizeof(trampoline_bytes))) // Patch the gate.
			return false;

		return true;
	}
}