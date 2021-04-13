#include "Windows.h"
#include <cstdio>
#include <iostream>

import syscall;

int main()
{
    SIZE_T size = 3000;
    PVOID ptr = nullptr;
    NTSTATUS test = syscall::NtAllocateVirtualMemory((HANDLE)-1, &ptr, NULL, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    NTSTATUS test2 = syscall::NtFreeVirtualMemory((HANDLE)-1, &ptr, &size, MEM_RELEASE);

    while (true)
    {
        Sleep(500);
    }

    return 0;
}