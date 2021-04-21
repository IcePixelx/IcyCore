module;

#include "Windows.h"
#include <iostream>
#include <string>
#include <map>

export module heavensgate;

import modules;
import syscall;
import memory;

export namespace Heavensgate
{
	namespace Ordinal
	{
		std::int32_t nt_allocate_virtual_memory = 0x0; // The ordinal index for NtAllocateVirtualMemory
	}

	void* new_heavens_gate = nullptr; // Future new memory location of the 'Heavensgate'
	Modulemanager::MemoryModules* ntdll = nullptr; // Pointer to ntdll.dll

	/*
	*  This is our function that NtAllocateVirtualMemory calls will get redirected to before reaching the callee.
	*  
	*  Every parameter can be changed and modified.
	*  To grab the actual return value you have to perform inline assembly to grab EAX from the stack.
	* 
	*  Example below.
	*
	*  DWORD _eax = 0;
	*  __asm
	*  {
	*     mov _eax, eax
	*  }
	*
	*  @calling convention: NtAllocateVirtualMemory is normally a __stdcall (NTAPI) function. If we don't force this calling convention the program will crash upon returning in this hooked function.
	*  @param:              Parameters also have to be the same as NtAllocateVirtualMemory otherwise the compiler will mess up the stack and crash us.
	*  @return:             Any NTSTATUS code you wanna return.
	*/

	NTSTATUS NTAPI hkNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
	{
		return 0xC00000E5; // Return STATUS_INTERNAL_ERROR.
	}


	/*
    *  This function checks if the NTAPI function performs a system call and if it does it will read the ordinal index for it.
    *
    *  Grabs the function via the export table in ntdll.dll
    *  Check if NTAPI function is valid and if the first byte is 0xB8
    *  If true we move 1 byte forwards and grab the 4 byte long ordinal index.
    *
    *  @calling convention: Compiler handled.
    *  @parameters:         Constant std::string containing the wanted NTAPI function name.
    *  @return              Ordinal index or if NTAPI function is not valid -1.
    */

	std::int32_t GetOrdinal(const std::string ntapi)
	{
		MemoryAddress api = ntdll->GetExportedFunction(ntapi);

		if (api && api.CheckBytes({ 0xB8 })) // Valid function that performs a system call?
		{
			return api.OffsetSelf().GetValue<std::int32_t>(); // If yes return the next 4 bytes which will be the ordinal.
		}

		return -1; // Ordinal was not found.
	}

	/* 
	*  This function gets the 'Heavensgate' address.
	* 
	*  @calling convention: Compiler handled.
	*  @param:              None.
	*  @return:             'Heavensgate' address.
	*/

	MemoryAddress GetGateAddress()
	{
		return ntdll->GetExportedFunction("Wow64Transition").DerefSelf(); // Grab the export for the 'heavensgate' and dereference once to get the address.
	}

	/*
	*  This function is our hook for the 'heavensgate'.
	* 
	*  It uses in-line assembly to identify the currently called function and if its a function that should be hooked we manipulate the return address to point to our hooking function.
	* 
	*  So instead of the call order being.
	*  calle function > ntdll 32bit > wow64cpu > ntdll 64bit > windows kernel driver > ntdll 64bit > wow64cpu > ntdll 32 bit > callee function
	*
	*  We manipulate it to be.
	*  calle function > ntdll 32bit > wow64cpu > ntdll 64bit > windows kernel driver > ntdll 64bit > wow64cpu > ntdll 32 bit > OUR HOOK > callee function
	*
	*  That allows us to change the return value and manipulate parameters before the callee function gets actual access to it.
	*  
	*  @calling convention: __declspec(naked) is used so the compiler doesn't generate assembly that could mess up the stack.
	*  @param:             None.
	*  @return:            None.
	*/

	void __declspec(naked) hkWow64Transition()
	{
		// EAX holds the ordinal.
		__asm
		{
			cmp eax, Ordinal::nt_allocate_virtual_memory // Is the ordinal the virtualallocates one?
			je hook_nt_allocate_virtual_memory // If so jump to it.
			jmp call_original // Jump to original.

hook_nt_allocate_virtual_memory:
			mov eax, hkNtAllocateVirtualMemory // Move our func into eax.

		     /* 
			 *  From observing the last returnaddress always resides in [esp + 0].
			 *  With this we can modify eax which will be the return value after the actual syscall in 64bit went through.
			 *  So now we can modify parameters when our hook gets called and the returnvalue which gives us the complete control as when using a normal hook.
		     */

			mov [esp + 0], eax // Replace latest returnaddr with our func this will cause the original function to jump to our hook instead of its supposed destination.
			mov eax, Ordinal::nt_allocate_virtual_memory // Give eax the ordinal again.
			jmp call_original 

call_original:
			jmp new_heavens_gate // Jump to our new allocated heavensgate.
		}
	}

	/*
	*  This function applies our detour hook to the 'heavensgate'.
	* 
	*  @calling convention: Compiler handled.
	*  @parameters:         Pointer to the address of the 'heavensgate', pointer to the bytes that are gonna replace the 'heavensgate', array size of the bytes.
	*  @return              If any system call doesn't return STATUS_SUCCESS it will return false. Otherwise it will return true.
	*/

	bool PatchHeavensGate(void* gate_address, const void* detour_hook, const std::ptrdiff_t detour_hook_size)
	{
		ULONG protect_size = 16;
		ULONG old_protection = 0;

		// Change 'heavensgate' page protection so we can write to it.
		if (const NTSTATUS protect_status = Syscall::NtProtectVirtualMemory(reinterpret_cast<HANDLE>(-1), &gate_address, &protect_size, PAGE_EXECUTE_READWRITE, &old_protection);
			protect_status != 0) // 0 is STATUS_SUCCESS.
			return false;

		if (!memcpy(gate_address, detour_hook, detour_hook_size)) // Patch the gate so it points to our hook.
			return false;

		protect_size = 16; // NtProtectvirtualMemory modifies protect_size to 1000 so we need to reset it.

		// Restore page protection of the 'heavensgate'.
		if (const NTSTATUS protect_status = Syscall::NtProtectVirtualMemory(reinterpret_cast<HANDLE>(-1), &gate_address, &protect_size, old_protection, &old_protection);
			protect_status != 0) // 0 is STATUS_SUCCESS.
			return false;

		return true;
	}

	/*
	*  This function is responsible for grabbing all the ordinal index of the functions we want to hook.
	* 
	*  @calling convention: Compiler handled.
	*  @paramters:          None.
	*  @return              Returns false if any of the ordinals could not be found. Otherwise it will return true.
	*/

	bool SetupOrdinals()
	{
		Ordinal::nt_allocate_virtual_memory = GetOrdinal("NtAllocateVirtualMemory"); // Grab the ordinal for NtAllocateVirtualMemory.
		if (Ordinal::nt_allocate_virtual_memory == -1) // Ordinal was not found.
			return false;

		return true;
	}

	/*
	*  Main function that does the setup needed for hooking the 'heavensgate'.
	* 
	*  @calling convention: Compiler handled.
	*  @parameters:         None
	*  @return:             If setting up the ordinals, the 'heavensgate' is not valid, any of the memcmpy calls fail, allocating the code section fails or if patching the 'heavensgate' fails we return false. Otherwise true.
	*/

	bool HookHeavensGate()
	{
		ntdll = Modulemanager::GetModule("ntdll.dll"); // Get a pointer to the ntdll.dll module.

		if (!SetupOrdinals()) // Grab all the ordinals for the functions we wanna hook.
			return false;

		if (!GetGateAddress()) // Is the 'heavensgate' export valid.
			return false;

		void* hook_gate = &hkWow64Transition; // Grab the address of our hooking function.

		/* 
		*  Push Detour.
		*  Basically a jmp but we push a new returnaddress onto the stack and pop it with ret to get to that location.
		*/ 
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

		if (!new_heavens_gate) // Is the allocated code section valid?
			return false;

		if (!memcpy(new_heavens_gate, GetGateAddress(), 9)) // Copy the gate into our allocated code section.
			return false;

		if (!PatchHeavensGate(GetGateAddress(), trampoline_bytes, sizeof(trampoline_bytes))) // Patch the 'heavensgate'.
			return false;

		return true;
	}
}