#include "Windows.h"
#include <cstdio>
#include <iostream>
#include <vector>

import syscall;
import memory;
import modules;
import heavensgate;

/*
*  Macro to easily to do any system call from a typedef.
*  
*  @parameters: t = typedef of any function.
*  return:      NTSTATUS of system called function.
*/

#define SYSTEMCALL(t) syscall::SystemCall<t>(#t)

/*
*   Main function of application.
* 
*   @calling convention: Compiler handled.
*   @parameters:         Can be used when the application gets launched with extra commandline parameters.
*   @return:             Error-Codes or Success Codes.
*/

int main(int argc, char* argv[])
{
    Modulemanager::GetModules(); // Get all modules from the process environment block.
    
    if (!Heavensgate::HookHeavensGate()) // Hook the 'heavensgate'.
        return 0; // It failed? Stop further execution.

    SIZE_T allocation_size = 3000;
    PVOID pointer_reference = nullptr;

    NTSTATUS allocate_result = Syscall::NtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &pointer_reference, NULL, &allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate new code section.
    NTSTATUS free_result = Syscall::NtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &pointer_reference, &allocation_size, MEM_RELEASE); // Free new allocated code section.

    pointer_reference = nullptr; // Null the pointer because we free'd the allocated code section.

    std::cout << "NTSTATUS allocate_result = 0x" << std::uppercase << std::hex << allocate_result << ";" << std::endl;
    std::cout << "NTSTATUS free_result = 0x" << std::uppercase << std::hex << free_result << ";" << std::endl;
    std::cout << "Is ptr still valid? " << pointer_reference << std::endl;

    getchar(); // Wait for input.

    return 0;
}