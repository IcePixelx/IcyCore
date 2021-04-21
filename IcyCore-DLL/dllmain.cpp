#include "Windows.h"
#include <cstdio>
#include <iostream>

import syscall;
import heavensgate;
import modules;

/*
*  Macro to easily to do any system call from a typedef.
*
*  @parameters: t = typedef of any function.
*  return:      NTSTATUS of system called function.
*/

#define SYSTEMCALL(t) syscall::SystemCall<t>(#t)

/*
*   Entry point of our dynamic linked library.
*
*   @calling convention: APIENTRY (__stdcall)
*   @parameters:         HMODULE module holds the module causing the call, DWORD ul_reason_for_call holds the reason on why DllMain got called, LPVOID reserved if the process is getting terminated its non NULL.
*   @return:             Either true or false.
*/

BOOL APIENTRY DllMain(HMODULE module, DWORD ul_reason_for_call, LPVOID reserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        Modulemanager::GetModules(); // Get all modules from the process environment block.

        if (!Heavensgate::HookHeavensGate()) // Hook the 'heavensgate'.
            return 0; // It failed? Stop further execution.

        SIZE_T allocation_size = 3000;
        PVOID pointer_reference = nullptr;

        NTSTATUS allocate_result = Syscall::NtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &pointer_reference, NULL, &allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate new code section.
        NTSTATUS free_result = Syscall::NtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pointer_reference, &allocation_size, MEM_RELEASE); // Free new allocated code section.

        pointer_reference = nullptr; // Null the pointer because we free'd the allocated code section.

        return TRUE;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}

