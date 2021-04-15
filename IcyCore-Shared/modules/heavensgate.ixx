module;

#include "Windows.h"
#include <iostream>
#include <map>

export module heavensgate;

export namespace heavensgate
{
	namespace ordinal
	{
		std::int32_t nt_allocate_virtual_memory = 0x0;
	}

	// Variables
	void* new_heavens_gate = nullptr;
	void* map_return_address = nullptr;
	HMODULE ntdll = nullptr;

	// Pre-Define
	std::int32_t GetOrdinal(const HMODULE ntdll, const char* ntapi);

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
			mov[esp + 0], eax // Replace latest returnaddr with our func this will cause the original function to jump to our hook instead of its supposed destination.
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
		ntdll = GetModuleHandleA("ntdll.dll");
		ordinal::nt_allocate_virtual_memory = GetOrdinal(ntdll, "NtAllocateVirtualMemory");
		if (ordinal::nt_allocate_virtual_memory == -1) // Ordinal was not found.
			return false;

		return true;
	}

	std::int32_t GetOrdinal(const HMODULE ntdll, const char* ntapi)
	{
		void* api = GetProcAddress(ntdll, ntapi); // Grab NT function.

		if (api && *reinterpret_cast<BYTE*>(api) == 0xB8) // Valid function that performs a system call?
		{
			return *reinterpret_cast<std::int32_t*>(reinterpret_cast<std::int32_t>(api) + 0x1); // If yes return the next 4 bytes which will be the ordinal.
		}

		return -1; // error handling.
	}

	bool PatchHeavensGate(void* gate_address, void* buffer, const std::ptrdiff_t size)
	{
		DWORD old_protect = 0; // Use Windows definitions for passing into Windows API functions.
		if (!VirtualProtect(gate_address, 16, PAGE_EXECUTE_READWRITE, &old_protect)) // Change the protection of the gate so we can write to it.
			return false;

		if (!memcpy(gate_address, buffer, size)) // Patch the gate.
			return false;

		if (!VirtualProtect(gate_address, 16, old_protect, &old_protect)) // Restore protection of the gate.
			return false;

		return true;
	}

	bool HookHeavensGate()
	{
		if (!GetGateAddress())
			return false;

		void* hook_gate = &hkWow64Transition; // Grab our hooks addr.

		if (!hook_gate)
			return false;

		// Push Detour.
		// Basically a jmp but we push a new returnaddr onto the stack and pop it with ret to get to that location.
		std::uint8_t trampoline_bytes[] =
		{
			0x68, 0x00, 0x00, 0x00, 0x00,       // push 0xADDRESS
			0xC3,                               // ret
			0x90, 0x90, 0x90                    // nop, nop, nop
		};

		if (!memcpy(&trampoline_bytes[1], &hook_gate, 4)) // Copy our function address into the trampoline.
			return false;

		new_heavens_gate = VirtualAlloc(nullptr, 16, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); // Allocate new memory for the heavens gate copy.
		if (!new_heavens_gate)
			return false;

		if (!memcpy(new_heavens_gate, GetGateAddress(), 9)) // Copy the gate into our allocated memory.
			return false;

		if (!PatchHeavensGate(GetGateAddress(), trampoline_bytes, sizeof(trampoline_bytes))) // Patch the gate.
			return false;

		return true;
	}
}